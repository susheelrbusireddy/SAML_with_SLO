using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.MvcCore;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Okta_SAML_Example.Identity;
using Microsoft.Extensions.Options;
using System.Security.Authentication;
using System.Xml;
using System.Net;
using RestSharp;
using System.Text;
using System;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;


namespace Okta_SAML_Example.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class Controllers : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;

        public Controllers(IOptions<Saml2Configuration> configAccessor)
        {
            config = configAccessor.Value;
        }

        [Route("Login")]
        public IActionResult Login(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config)).ToActionResult();
        }

        [Route("AssertionConsumerService")]
        public async Task<IActionResult> AssertionConsumerService()
        {       
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(config);

            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }
            string SAMLresp = saml2AuthnResponse.XmlDocument.InnerXml.ToString();
            XmlDocument xmldoc = new XmlDocument();
            xmldoc.LoadXml(SAMLresp);

            XmlNodeList xmlnode = xmldoc.GetElementsByTagName("saml2:Assertion");
            string assertionTag = xmlnode[0].OuterXml.ToString();
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(assertionTag);
            string base64Assertion = System.Convert.ToBase64String(plainTextBytes);

            binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(claimsPrincipal));

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return Redirect(returnUrl);
        }

        [HttpPost("Logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            var saml2LogoutRequest = await new Saml2LogoutRequest(config, User).DeleteSession(HttpContext);
            string logoutRequestID = saml2LogoutRequest.IdAsString.ToString();

            return binding.Bind(saml2LogoutRequest).ToActionResult();
        }

        [Route("SingleLogout")]
        public IActionResult SingleLogout()
        {
            var responsebinding = new Saml2PostBinding();
            var saml2LogoutResponse = new Saml2LogoutResponse(config);

            responsebinding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2LogoutResponse);
            if (saml2LogoutResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2LogoutResponse.Status}");
            }
            return Redirect("~/");
        }
    }
}
