package github

// githubCall reaches api.github.com. It is a variable so a test can stand in
// for GitHub, which needs a network, a token and a repository nobody owns here.
var githubCall = ghCall
