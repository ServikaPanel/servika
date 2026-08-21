-- 0112 - a notification has to be readable in the language the panel is drawing.
--
-- 0111 gave notifications a title and a message, which are English. The panel
-- renders twelve languages and a notification is UI text like any other, so
-- stored English is the one thing this screen cannot show: the text is written
-- when the event happens and read later by somebody whose language nothing knew
-- at that moment.
--
-- message_key names a string the frontend owns and params carries the values it
-- interpolates, so the sentence is composed in the READER's language. The
-- English title and message stay as the fallback: a client that does not know
-- the key still has something to show, and a key is not a sentence in a log.
--
-- Both default to empty rather than NULL, so "no key" is one value rather than
-- two, and a writer that supplies only English is still valid.
ALTER TABLE notifications
  ADD COLUMN message_key VARCHAR(64) NOT NULL DEFAULT '' AFTER message,
  ADD COLUMN params TEXT NOT NULL AFTER message_key;
