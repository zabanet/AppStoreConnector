using AppStoreConnector;

namespace AppStoreConnectorTests
{
    public class ConnectorTests
    {
        private readonly string KeyId = "TEST_ID_123";
        private readonly string PrivateKeyPath = @"C:\Temp\ApiKey_TEST_ID_123.p8";
        private readonly string IssuerId = "aa123456-b1234-12cc-1234-ddd123456789";

        [Fact]
        public async Task ConnectAsIndividualReturnsSuccess()
        {
            var result = await Connector.ConnectWithIndividualKey(KeyId, PrivateKeyPath);
            Assert.True(result);
        }

        [Fact]
        public async Task ConnectWithTeamKeyReturnsSuccess()
        {
            var result = await Connector.ConnectWithTeamKey(KeyId, IssuerId, PrivateKeyPath);
            Assert.True(result);
        }
    }
}