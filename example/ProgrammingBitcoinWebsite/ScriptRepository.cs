using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using NBitcoin;
using NBitcoin.DataEncoders;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProgrammingBitcoinFunding
{
    public class SavedScript
    {
        public SavedScript()
        {
            Id = Guid.NewGuid();
        }
        public Guid Id
        {
            get;
            set;
        }
        public string ScriptSig
        {
            get;
            set;
        }
        public string ScriptPubKey
        {
            get;
            set;
        }
    }
    public class ScriptRepository
    {
        public ScriptRepository()
        {

        }

        public CloudTable GetTable()
        {
            return CloudStorageAccount.Parse(ConfigurationManager.AppSettings["AzureStorage"]).CreateCloudTableClient().GetTableReference("SavedScripts");
        }
        public void InsertScript(SavedScript script)
        {
            var table = GetTable();
            var entity = new DynamicTableEntity();
            entity.ETag = "*";
            entity.PartitionKey = "1";
            entity.RowKey = script.Id.ToString();
            entity.Properties.Add("Script", new EntityProperty(Serialize(script)));
            table.Execute(TableOperation.Insert(entity));
        }

        private string Serialize(SavedScript script)
        {
            return JsonConvert.SerializeObject(script);
        }
        private T Deserialize<T>(string script)
        {
            return JsonConvert.DeserializeObject<T>(script);
        }
        public SavedScript GetScript(Guid id)
        {
            var table = GetTable();
            var entity = table.ExecuteQuery(new TableQuery()
            {
                FilterString = TableQuery.CombineFilters
                (
                    TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, "1"),
                    TableOperators.And,
                    TableQuery.GenerateFilterCondition("RowKey", QueryComparisons.Equal, id.ToString())
                )
            }).FirstOrDefault();
            if(entity == null)
                return null;
            return Deserialize<SavedScript>(entity["Script"].StringValue);
        }        
    }
}
