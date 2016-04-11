using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(ProgrammingBitcoinFunding.Startup))]
namespace ProgrammingBitcoinFunding
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {

        }
    }
}
