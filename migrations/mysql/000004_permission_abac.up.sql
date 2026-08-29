ALTER TABLE permissions ADD COLUMN condition_expression TEXT NULL;
UPDATE permissions SET condition_expression = '' WHERE condition_expression IS NULL;
ALTER TABLE permissions MODIFY COLUMN condition_expression TEXT NOT NULL;
