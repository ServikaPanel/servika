-- Clear a customer's plan_id when it names a plan that no longer exists.
--
-- WHY: the "plan in use" guard counted domains.plan_id only, so a plan that only
-- customers referenced could be deleted, and the write path stored any id at all
-- because customers.plan_id carries no foreign key. Every count quota then read
-- that customer's plan, found nothing, and returned a raw sql.ErrNoRows that its
-- caller reports as a 500: a durable denial of database, mailbox, application
-- and addon-domain creation, with a message that names no cause.
--
-- Both holes are closed in the same change, but an installation that already
-- carries a dangling id stays broken until the row is repaired.
--
-- NULL is the right repair, not a substituted plan. NULL means "on no plan",
-- which every count gate passes through, and it is a state an operator can see
-- and correct on the customers screen. Guessing a plan would silently move a
-- billed tier boundary.

UPDATE customers
   SET plan_id = NULL
 WHERE plan_id IS NOT NULL
   AND plan_id NOT IN (SELECT id FROM service_plans);
