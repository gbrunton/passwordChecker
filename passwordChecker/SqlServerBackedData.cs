﻿using System;
using System.Data;
using System.Data.SqlClient;

namespace passwordChecker
{
    public class SqlServerBackedData
    {
        public void Implement()
        {
            var stringBuilder = new SqlConnectionStringBuilder(@"data source=.;Initial Catalog=Passwords;Integrated Security=SSPI;");
            //CreateDb(stringBuilder);
            //InsertData(stringBuilder, @"c:\temp\");

            while (true)
            {
                Console.Write("Enter password: ");
                Console.WriteLine();
                var hashString = Program.SHA1HashStringForUTF8String(Program.GetPasswordFromConsole());
                using (var connection = new SqlConnection(stringBuilder.ConnectionString))
                using (var command = connection.CreateCommand())
                {
                    var sqlParameter = command.CreateParameter();
                    sqlParameter.ParameterName = "Password";
                    sqlParameter.SqlDbType = SqlDbType.Char;
                    sqlParameter.SqlValue = hashString;
                    command.Parameters.Add(sqlParameter);

                    command.CommandText = "Select * From Password Where Value = @Password;";
                    connection.Open();
                    var result = command.ExecuteScalar() as string;
                    Console.WriteLine(!string.IsNullOrWhiteSpace(result)
                        ? "Password has been breeched."
                        : "You are safe to continue to use this password.");
                }
            }
        }

        private static void InsertData(SqlConnectionStringBuilder stringBuilder, string pathToPasswordTextFile)
        {
            using (var connection = new SqlConnection(stringBuilder.ConnectionString))
            using (var command = connection.CreateCommand())
            {
                command.CommandTimeout = 0;
                connection.Open();

                command.CommandText = $@"BULK INSERT Passwords.dbo.Password  
   FROM '{pathToPasswordTextFile}'  
   WITH   
      (           
         ROWTERMINATOR ='\n',
         BATCHSIZE = 100000
      ); 

CREATE NONCLUSTERED INDEX [Password_Value_Index] ON [Password] ([Value]);
";
                command.ExecuteNonQuery();
            }
        }

        private static void CreateDb(SqlConnectionStringBuilder connectionStringBuilder)
        {
            var db = connectionStringBuilder.InitialCatalog;
            connectionStringBuilder.InitialCatalog = "master";
            using (var connection = new SqlConnection(connectionStringBuilder.ConnectionString))
            using (var command = connection.CreateCommand())
            {
                command.CommandText = @"CREATE DATABASE [Passwords]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'Passwords', FILENAME = N'E:\msqlData\Passwords.mdf' , SIZE = 4096KB , FILEGROWTH = 1024KB )
 LOG ON 
( NAME = N'Passwords_log', FILENAME = N'E:\msqlData\Passwords_log.ldf' , SIZE = 1024KB , FILEGROWTH = 10%)";
                connection.Open();
                command.ExecuteNonQuery();

                throw new Exception("This will create the db in the master database!");
                command.CommandText = @"ALTER DATABASE [Passwords] SET COMPATIBILITY_LEVEL = 120

ALTER DATABASE [Passwords] SET ANSI_NULL_DEFAULT OFF 

ALTER DATABASE [Passwords] SET ANSI_NULLS OFF 

ALTER DATABASE [Passwords] SET ANSI_PADDING OFF 

ALTER DATABASE [Passwords] SET ANSI_WARNINGS OFF 

ALTER DATABASE [Passwords] SET ARITHABORT OFF 

ALTER DATABASE [Passwords] SET AUTO_CLOSE OFF 

ALTER DATABASE [Passwords] SET AUTO_SHRINK OFF 

ALTER DATABASE [Passwords] SET AUTO_CREATE_STATISTICS ON(INCREMENTAL = OFF)

ALTER DATABASE [Passwords] SET AUTO_UPDATE_STATISTICS ON 

ALTER DATABASE [Passwords] SET CURSOR_CLOSE_ON_COMMIT OFF 

ALTER DATABASE [Passwords] SET CURSOR_DEFAULT  GLOBAL 

ALTER DATABASE [Passwords] SET CONCAT_NULL_YIELDS_NULL OFF 

ALTER DATABASE [Passwords] SET NUMERIC_ROUNDABORT OFF 

ALTER DATABASE [Passwords] SET QUOTED_IDENTIFIER OFF 

ALTER DATABASE [Passwords] SET RECURSIVE_TRIGGERS OFF 

ALTER DATABASE [Passwords] SET  DISABLE_BROKER 

ALTER DATABASE [Passwords] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 

ALTER DATABASE [Passwords] SET DATE_CORRELATION_OPTIMIZATION OFF 

ALTER DATABASE [Passwords] SET PARAMETERIZATION SIMPLE 

ALTER DATABASE [Passwords] SET READ_COMMITTED_SNAPSHOT OFF 

ALTER DATABASE [Passwords] SET  READ_WRITE 

ALTER DATABASE [Passwords] SET RECOVERY SIMPLE 

ALTER DATABASE [Passwords] SET  MULTI_USER 

ALTER DATABASE [Passwords] SET PAGE_VERIFY CHECKSUM  

ALTER DATABASE [Passwords] SET TARGET_RECOVERY_TIME = 0 SECONDS 

ALTER DATABASE [Passwords] SET DELAYED_DURABILITY = DISABLED 

USE [Passwords]

IF NOT EXISTS (SELECT name FROM sys.filegroups WHERE is_default=1 AND name = N'PRIMARY') ALTER DATABASE [Passwords] MODIFY FILEGROUP [PRIMARY] DEFAULT

CREATE TABLE [dbo].[Password] 
(
	Value CHAR(40) NOT NULL
);
";
                command.ExecuteNonQuery();
            }

            connectionStringBuilder.InitialCatalog = db;
        }
    }
}