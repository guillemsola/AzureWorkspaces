CREATE DATABASE Workspace; 
GO

CREATE LOGIN WSAdmin
WITH PASSWORD = 'workspace2017!', 
DEFAULT_DATABASE = Workspace, 
CHECK_POLICY = OFF,
CHECK_EXPIRATION = OFF;
GO

USE Workspace

CREATE USER WSAdmin 
 FOR LOGIN WSAdmin; 

EXEC sp_addrolemember N'db_owner', N'WSAdmin';

EXEC sp_addrolemember N'db_securityadmin', N'WSAdmin';
GO


CREATE LOGIN WSUser
WITH PASSWORD = 'workspace2017!', 
DEFAULT_DATABASE = Workspace, 
CHECK_POLICY = OFF,
CHECK_EXPIRATION = OFF;
GO

USE Workspace

CREATE USER WSUser 
 FOR LOGIN WSUser; 

EXEC sp_addrolemember N'db_owner', N'WSUser';

EXEC sp_addrolemember N'db_securityadmin', N'WSUser';
GO



CREATE DATABASE WorkspaceConsole; 
GO

CREATE LOGIN ConsoleUser
WITH PASSWORD = 'workspace2017!', 
DEFAULT_DATABASE = WorkspaceConsole, 
CHECK_POLICY = OFF,
CHECK_EXPIRATION = OFF;
GO

USE WorkspaceConsole

CREATE USER ConsoleUser 
 FOR LOGIN ConsoleUser; 

EXEC sp_addrolemember N'db_owner', N'ConsoleUser';

EXEC sp_addrolemember N'db_securityadmin', N'ConsoleUser';
GO


CREATE DATABASE CloudRobotWorkflowInstanceStore; 
GO

CREATE LOGIN CloudRobotInstanceStoreAdmin
WITH PASSWORD = 'workspace2017!', 
DEFAULT_DATABASE = CloudRobotWorkflowInstanceStore, 
CHECK_POLICY = OFF,
CHECK_EXPIRATION = OFF;
GO

USE CloudRobotWorkflowInstanceStore

CREATE USER CloudRobotInstanceStoreAdmin 
 FOR LOGIN CloudRobotInstanceStoreAdmin; 

EXEC sp_addrolemember N'db_owner', N'CloudRobotInstanceStoreAdmin';

EXEC sp_addrolemember N'db_securityadmin', N'CloudRobotInstanceStoreAdmin';
GO



CREATE DATABASE AsgScheduler; 
GO

CREATE LOGIN SchedulerAdmin
WITH PASSWORD = 'workspace2017!', 
DEFAULT_DATABASE = AsgScheduler, 
CHECK_POLICY = OFF,
CHECK_EXPIRATION = OFF;
GO

USE AsgScheduler

CREATE USER SchedulerAdmin 
 FOR LOGIN SchedulerAdmin; 

EXEC sp_addrolemember N'db_owner', N'SchedulerAdmin';

EXEC sp_addrolemember N'db_securityadmin', N'SchedulerAdmin';
GO
