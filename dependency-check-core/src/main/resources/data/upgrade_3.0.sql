--upgrading the minor version allows older instances of ODC to connect.
UPDATE Properties SET value='3.1' WHERE ID='version';

DROP TABLE IF EXISTS central;

CREATE TABLE central (sha1 CHAR(40), groupId VARCHAR(500), artifactId VARCHAR(500),
    version VARCHAR(100), artifactUrl VARCHAR(1000), pomUrl VARCHAR(1000), createdOn DATE);

CREATE INDEX idxCentral ON central(sha1);
