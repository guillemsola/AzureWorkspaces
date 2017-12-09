if (select count(name) from sys.databases where name = 'Workspace') = 0
BEGIN
	RAISERROR ('Did not find database [Workspace]', 16, 1)
END
ELSE
BEGIN
	PRINT 'Found database [Workspace]'
END