package backups

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"servika/internal/netguard"
)

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// s3HTTPClient talks to the object-storage endpoint recorded on a backup
// destination. That endpoint is customer-configurable (the routes are
// CustomerScope), so the dialer refuses loopback, RFC1918, link-local and the
// cloud metadata address. The check runs on the concrete IP at dial time, which
// also closes DNS rebinding: a name that answers public for an upfront lookup
// and private a moment later is still refused here.
var s3HTTPClient = &http.Client{
	Timeout: 30 * time.Minute,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   netguard.DialControl,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	},
}

func s3Endpoint(d *Destination) (*url.URL, error) {
	raw := strings.TrimSpace(d.Endpoint)
	if raw == "" {
		if d.Type == "b2" {
			return nil, fmt.Errorf("a Backblaze S3 endpoint is required")
		}
		region := d.Region
		if region == "" {
			region = "us-east-1"
		}
		if region == "us-east-1" {
			raw = "https://s3.amazonaws.com"
		} else {
			raw = "https://s3." + region + ".amazonaws.com"
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("the endpoint must be a valid HTTPS address")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("the endpoint cannot contain a query or fragment")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}

func s3RequestURL(d *Destination, objectName string) (*url.URL, error) {
	u, err := s3Endpoint(d)
	if err != nil {
		return nil, err
	}
	bucket := strings.TrimSpace(d.Bucket)
	if bucket == "" {
		return nil, fmt.Errorf("a bucket is required")
	}
	parts := []string{strings.Trim(u.Path, "/")}
	if d.PathStyle {
		parts = append(parts, bucket)
	} else {
		u.Host = bucket + "." + u.Host
	}
	prefix := strings.Trim(d.RemoteDir, "/")
	if prefix != "" {
		parts = append(parts, prefix)
	}
	if objectName != "" {
		parts = append(parts, objectName)
	}
	u.Path = "/" + path.Join(parts...)
	return u, nil
}

func uploadS3Object(ctx context.Context, d *Destination, localPath, objectName string) error {
	// #nosec G703 G304 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil {
		_ = f.Close()
		return fmt.Errorf("backup hash: %w", err)
	}
	info, err := f.Stat()
	_ = f.Close()
	if err != nil {
		return err
	}
	payloadHash := hex.EncodeToString(hash.Sum(nil))
	u, err := s3RequestURL(d, objectName)
	if err != nil {
		return err
	}
	// #nosec G703 G304 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	body, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()
	// #nosec G704 -- URL derives from the destination's own S3 endpoint, validated as HTTPS in s3Endpoint and checked against internal ranges in doS3Request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), body)
	if err != nil {
		return err
	}
	req.ContentLength = info.Size()
	req.Header.Set("Content-Type", "application/gzip")
	signS3Request(req, d, payloadHash, time.Now().UTC())
	return doS3Request(req)
}

func testS3Connection(ctx context.Context, d *Destination) error {
	u, err := s3RequestURL(d, "")
	if err != nil {
		return err
	}
	// #nosec G704 -- URL derives from the destination's own S3 endpoint, validated as HTTPS in s3Endpoint and checked against internal ranges in doS3Request.
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return err
	}
	signS3Request(req, d, emptySHA256, time.Now().UTC())
	return doS3Request(req)
}

// headS3Object returns the stored object's size in bytes, so an upload can be
// verified against the local file. A HEAD answers with Content-Length and no
// body. A read failure returns -1, which the caller treats as "could not
// verify" rather than "size mismatch", so a transient HEAD error never flags a
// good upload as corrupt.
func headS3Object(ctx context.Context, d *Destination, objectName string) int64 {
	u, err := s3RequestURL(d, objectName)
	if err != nil {
		return -1
	}
	// #nosec G704 -- URL derives from the destination's own S3 endpoint, validated as HTTPS in s3Endpoint and checked against internal ranges below and at dial time.
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return -1
	}
	signS3Request(req, d, emptySHA256, time.Now().UTC())
	if err := requireExternalEndpoint(req); err != nil {
		return -1
	}
	// #nosec G704 -- request target derives from the destination's own S3 endpoint, validated as HTTPS in s3Endpoint and checked against internal ranges above and at dial time.
	resp, err := s3HTTPClient.Do(req)
	if err != nil {
		return -1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return -1
	}
	if resp.ContentLength < 0 {
		return -1
	}
	return resp.ContentLength
}

func downloadS3Object(ctx context.Context, d *Destination, objectName, localPath string) error {
	u, err := s3RequestURL(d, objectName)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	signS3Request(req, d, emptySHA256, time.Now().UTC())
	if err := requireExternalEndpoint(req); err != nil {
		return err
	}
	// #nosec G704 -- request target derives from the destination's own S3 endpoint, validated as HTTPS in s3Endpoint and checked against internal ranges above and at dial time.
	resp, err := s3HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("S3 %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	tmp := localPath + ".part"
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, resp.Body)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, localPath)
}

func deleteS3Object(ctx context.Context, d *Destination, objectName string) error {
	u, err := s3RequestURL(d, objectName)
	if err != nil {
		return err
	}
	// #nosec G704 -- URL derives from the destination's own S3 endpoint, validated as HTTPS in s3Endpoint and checked against internal ranges in doS3Request.
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return err
	}
	signS3Request(req, d, emptySHA256, time.Now().UTC())
	return doS3Request(req)
}

// requireExternalEndpoint refuses a destination whose endpoint resolves into an
// internal network. The dialer already refuses it, but only with a bare dial
// error; this names the cause for the operator. Every request must call it,
// including downloadS3Object, which streams its response and does not go
// through doS3Request.
func requireExternalEndpoint(req *http.Request) error {
	if err := netguard.CheckHost(req.URL.Hostname()); err != nil {
		return fmt.Errorf("the S3 endpoint is not permitted: %w", err)
	}
	return nil
}

func doS3Request(req *http.Request) error {
	if err := requireExternalEndpoint(req); err != nil {
		return err
	}
	// #nosec G704 -- request target derives from the destination's own S3 endpoint, validated as HTTPS in s3Endpoint and checked against internal ranges above and at dial time.
	resp, err := s3HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	detail := strings.TrimSpace(string(msg))
	if detail == "" {
		detail = resp.Status
	}
	return fmt.Errorf("S3 %s: %s", resp.Status, detail)
}

func signS3Request(req *http.Request, d *Destination, payloadHash string, now time.Time) {
	region := d.Region
	if region == "" {
		region = "us-east-1"
	}
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonicalHeaders := "host:" + req.URL.Host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := req.Method + "\n" + req.URL.EscapedPath() + "\n" +
		req.URL.Query().Encode() + "\n" + canonicalHeaders + "\n" +
		signedHeaders + "\n" + payloadHash
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	scope := date + "/" + region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" +
		hex.EncodeToString(requestHash[:])

	dateKey := hmacSHA256([]byte("AWS4"+d.Password), date)
	regionKey := hmacSHA256(dateKey, region)
	serviceKey := hmacSHA256(regionKey, "s3")
	signingKey := hmacSHA256(serviceKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+d.Username+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
