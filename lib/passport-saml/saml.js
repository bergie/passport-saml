var zlib = require('zlib');
var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');

var SAML = function (options) {
  this.options = this.initialize(options);
};

SAML.prototype.initialize = function (options) {
  if (!options) {
    options = {};
  }

  if (!options.protocol) {
    options.protocol = 'https://';
  }

  if (!options.path) {
    options.path = '/saml/consume';
  }

  if (!options.issuer) {
    options.issuer = 'onelogin_saml';
  }

  if (options.identifierFormat === undefined) {
    options.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
  }

  return options;
};

SAML.prototype.generateUniqueID = function () {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
};

SAML.prototype.generateInstant = function () {
  var date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + (date.getUTCHours()+2)).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z"; 
};

SAML.prototype.signRequest = function (xml) {
  var signer = crypto.createSign('RSA-SHA1');
  signer.update(xml);
  return signer.sign(this.options.privateCert, 'base64');
}

SAML.prototype.generateRequest = function (req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  // Post-auth destination
  if (this.options.callbackUrl) {
    callbackUrl = this.options.callbackUrl;
  } else {
    var callbackUrl = this.options.protocol + req.headers.host + this.options.path;
  }

  var request =
   "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant + "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"" + callbackUrl + "\" Destination=\"" + this.options.entryPoint + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>\n";

  if (this.options.identifierFormat) {
    request += "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"" + this.options.identifierFormat + "\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n";
  }
   
  request += 
    "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
    "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n" +
  "</samlp:AuthnRequest>";

  return request;
};

SAML.prototype.getAuthorizeUrl = function (req, callback) {
  var self = this;
  var request = this.generateRequest(req);
  zlib.deflateRaw(request, function(err, buffer) {
    if (err) {
      return callback(err);
    }

    var base64   = buffer.toString('base64');
    var target = self.options.entryPoint + '?'

    var samlRequest = {
      SAMLRequest: base64
    };

    if (self.options.privateCert) {
      samlRequest.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
      samlRequest.Signature = self.signRequest(querystring.stringify(samlRequest));
    }
    target += querystring.stringify(samlRequest);

    callback(null, target);
  });
};

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

SAML.prototype.validateSignature = function (xml, cert) {
  var self = this;
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xmlCrypto.xpath.SelectNodes(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>"
    },
    getKey: function (keyInfo) {
      return self.certToPEM(cert);
    }
  };
  sig.loadSignature(signature.toString());
  return sig.checkSignature(xml);
};

SAML.prototype.getElement = function (parentElement, elementName) {
  if (parentElement['saml:' + elementName]) {
    return parentElement['saml:' + elementName];
  }
  return parentElement[elementName];
}

SAML.prototype.validateResponse = function (samlResponse, callback) {
  var self = this;
  var xml = new Buffer(samlResponse, 'base64').toString('ascii');
  var parser = new xml2js.Parser();
  parser.parseString(xml, function (err, doc) {
    // Verify signature
    if (self.options.cert && !self.validateSignature(xml, self.options.cert)) {
      return callback(new Error('Invalid signature'), null);
    }

    var assertion = self.getElement(doc, 'Assertion');
    if (!assertion) {
      return callback(new Error('Missing SAML assertion'), null);
    }

    profile = {};
    profile.issuer = self.getElement(assertion, 'Issuer');

    var attributeStatement = self.getElement(assertion, 'AttributeStatement');
    var attributes = self.getElement(attributeStatement, 'Attribute');
    attributes.forEach(function (attribute) {
      var value = self.getElement(attribute, 'AttributeValue');
      if (typeof value === 'string') {
        profile[attribute['@'].Name] = value;
        return;
      }
      profile[attribute['@'].Name] = value['#'];
    });

    if (!profile.mail && profile['urn:oid:0.9.2342.19200300.100.1.3']) {
      // See http://www.incommonfederation.org/attributesummary.html for definition of attribute OIDs
      profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3'];
    }

    if (!profile.email && profile.mail) {
      profile.email = profile.mail;
    }

    callback(null, profile);
  });
};

exports.SAML = SAML;
