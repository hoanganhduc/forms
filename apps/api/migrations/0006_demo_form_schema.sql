PRAGMA foreign_keys=ON;

UPDATE form_versions
SET schema_json='{"fields":[{"id":"first_name","type":"text","label":"First name","required":true},{"id":"email","type":"email","label":"Email","required":true},{"id":"start_date","type":"date","label":"Start date","required":true},{"id":"resume","type":"file","label":"Resume","required":false}]}'
WHERE form_id='form_hus_demo_1' AND version=1;
