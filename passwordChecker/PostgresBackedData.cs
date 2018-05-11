using System;
using System.Data;
using System.IO;
using Npgsql;
using NpgsqlTypes;

namespace passwordChecker
{
    public class PostgresBackedData
    {
        private const string PathToPasswordTextFile = @"";

        public void Implement()
        {
            var stringBuilder = new NpgsqlConnectionStringBuilder("Server=.;Port=5432;Database=pwned;Integrated Security=true;Max Auto Prepare=100;");
            //CreateDb(stringBuilder);
            //InsertData(stringBuilder);

            while (true)
            {
                Console.Write("Enter password: ");
                var hashString = Program.SHA1HashStringForUTF8String(Program.GetPasswordFromConsole());
                using (var connection = new NpgsqlConnection(stringBuilder.ConnectionString))
                using (var command = connection.CreateCommand())
                {
                    var sqlParameter = command.CreateParameter();
                    sqlParameter.ParameterName = "Password";
                    sqlParameter.DbType = DbType.String;
                    sqlParameter.Value = hashString.ToUpper();
                    command.Parameters.Add(sqlParameter);

                    command.CommandText = "Select FoundCount From Passwords_v2 Where Value = @Password;";
                    connection.Open();
                    var result = command.ExecuteScalar();
                    Console.WriteLine();
                    Console.WriteLine(result == null || result == DBNull.Value
                        ? "You are safe to continue to use this password."
                        : $"Password has been breeched. If was found '{(int)result:N0}' times.");
                }
            }
        }

        private void CreateDb(NpgsqlConnectionStringBuilder connectionStringBuilder)
        {
            var db = connectionStringBuilder.Database;
            connectionStringBuilder.Database = "postgres";
            using (var connection = new NpgsqlConnection(connectionStringBuilder.ConnectionString))
            using (var command = connection.CreateCommand())
            {
                command.CommandText = $@"CREATE DATABASE {db} WITH ENCODING='UTF8' CONNECTION LIMIT=-1;";
                connection.Open();
                command.ExecuteNonQuery();
            }

            connectionStringBuilder.Database = db;

            using (var connection = new NpgsqlConnection(connectionStringBuilder.ConnectionString))
            using (var command = connection.CreateCommand())
            {
            command.CommandText = @"
CREATE TABLE Passwords_v2(
	Value varchar(40) NOT NULL,
	FoundCount int NOT NULL
);
";
                connection.Open();
                command.ExecuteNonQuery();
            }
        }

        private static void InsertData(NpgsqlConnectionStringBuilder stringBuilder)
        {
            using (var connection = new NpgsqlConnection(stringBuilder.ConnectionString))
            {
                connection.Open();

                using (var writer = connection.BeginBinaryImport("COPY Passwords_v2 (value, foundcount) FROM STDIN (FORMAT BINARY)"))
                {
                    var rowNumber = 0;
                    foreach (var line in File.ReadLines(PathToPasswordTextFile))
                    {
                        var data = line.Split(':');
                        writer.StartRow();
                        writer.Write(data[0], NpgsqlDbType.Varchar);
                        writer.Write(data[1], NpgsqlDbType.Integer);
                        if (rowNumber % 500000 == 0)
                        {
                            Console.WriteLine($"Current rowNumber={rowNumber}");
                        }
                        rowNumber++;
                    }
                }

                Console.WriteLine("Creating Index");
                using (var command = connection.CreateCommand())
                using (var transaction = connection.BeginTransaction())
                {
                    command.CommandTimeout = 0;
                    command.CommandText = "CREATE INDEX Passwords_v2_On_Value_Index ON Passwords_v2 (Value ASC NULLS LAST);";
                    command.ExecuteNonQuery();
                    Console.WriteLine("Committing the transaction");
                    transaction.Commit();
                }
                Console.WriteLine("Index has been created");
            }
        }
    }
}