"use strict";
import * as express from "express";
import * as bodyParser from "body-parser";
import * as passport from "passport";
import { Profile, Strategy as SamlStrategy } from "../src";
import request = require("request");
import * as zlib from "zlib";
import * as querystring from "querystring";
import { parseString } from "xml2js";
import * as fs from "fs";
import { AuthenticateOptions, VerifiedCallback } from "../src/types";
import * as should from "should";
import { Server } from "http";
import { CapturedCheck, FAKE_CERT, SamlCheck } from "./types";

const capturedSamlRequestChecks: SamlCheck[] = [
  {
    name: "Empty Config",
    config: { cert: FAKE_CERT },
    result: {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          Destination: "https://wwwexampleIdp.com/saml",
        },
        "saml:Issuer": [
          { _: "onelogin_saml", $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" } },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
              AllowCreate: "true",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: { "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol", Comparison: "exact" },
            "saml:AuthnContextClassRef": [
              {
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
              },
            ],
          },
        ],
      },
    },
  },
  {
    name: "Empty Config w/ HTTP-POST binding",
    config: { authnRequestBinding: "HTTP-POST", cert: FAKE_CERT },
    result: {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          Destination: "https://wwwexampleIdp.com/saml",
        },
        "saml:Issuer": [
          { _: "onelogin_saml", $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" } },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
              AllowCreate: "true",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: { "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol", Comparison: "exact" },
            "saml:AuthnContextClassRef": [
              {
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
              },
            ],
          },
        ],
      },
    },
  },
  {
    name: "Config #2",
    config: {
      issuer: "http://exampleSp.com/saml",
      identifierFormat: "alternateIdentifier",
      passive: true,
      attributeConsumingServiceIndex: "123",
      forceAuthn: false,
      cert: FAKE_CERT,
    },
    result: {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          AttributeConsumingServiceIndex: "123",
          Destination: "https://wwwexampleIdp.com/saml",
          IsPassive: "true",
        },
        "saml:Issuer": [
          {
            _: "http://exampleSp.com/saml",
            $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              Format: "alternateIdentifier",
              AllowCreate: "true",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: { "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol", Comparison: "exact" },
            "saml:AuthnContextClassRef": [
              {
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
              },
            ],
          },
        ],
      },
    },
  },
  {
    name: "Uncompressed config #2",
    config: {
      issuer: "http://exampleSp.com/saml",
      identifierFormat: "alternateIdentifier",
      passive: true,
      attributeConsumingServiceIndex: "123",
      skipRequestCompression: true,
      cert: FAKE_CERT,
    },
    result: {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          AttributeConsumingServiceIndex: "123",
          Destination: "https://wwwexampleIdp.com/saml",
          IsPassive: "true",
        },
        "saml:Issuer": [
          {
            _: "http://exampleSp.com/saml",
            $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              Format: "alternateIdentifier",
              AllowCreate: "true",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: { "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol", Comparison: "exact" },
            "saml:AuthnContextClassRef": [
              {
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
              },
            ],
          },
        ],
      },
    },
  },
  {
    name: "Config #3",
    config: {
      issuer: "http://exampleSp.com/saml",
      identifierFormat: "alternateIdentifier",
      passive: true,
      attributeConsumingServiceIndex: "123",
      skipRequestCompression: true,
      disableRequestedAuthnContext: true,
      forceAuthn: true,
      cert: FAKE_CERT,
    },
    result: {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          AttributeConsumingServiceIndex: "123",
          Destination: "https://wwwexampleIdp.com/saml",
          IsPassive: "true",
          ForceAuthn: "true",
        },
        "saml:Issuer": [
          {
            _: "http://exampleSp.com/saml",
            $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              Format: "alternateIdentifier",
              AllowCreate: "true",
            },
          },
        ],
      },
    },
  },
  {
    name: "Config with AuthnContext",
    config: {
      issuer: "http://exampleSp.com/saml",
      identifierFormat: "alternateIdentifier",
      passive: true,
      attributeConsumingServiceIndex: "123",
      authnContext: ["myAuthnContext"],
      cert: FAKE_CERT,
    },
    result: {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          AttributeConsumingServiceIndex: "123",
          Destination: "https://wwwexampleIdp.com/saml",
          IsPassive: "true",
        },
        "saml:Issuer": [
          {
            _: "http://exampleSp.com/saml",
            $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              Format: "alternateIdentifier",
              AllowCreate: "true",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: { "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol", Comparison: "exact" },
            "saml:AuthnContextClassRef": [
              {
                _: "myAuthnContext",
                $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
              },
            ],
          },
        ],
      },
    },
  },
  {
    name: "Config with multiple AuthnContext",
    config: {
      issuer: "http://exampleSp.com/saml",
      identifierFormat: "alternateIdentifier",
      passive: true,
      attributeConsumingServiceIndex: "123",
      authnContext: ["myAuthnContext", "myAuthnContext2"],
      cert: FAKE_CERT,
    },
    result: {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          AttributeConsumingServiceIndex: "123",
          Destination: "https://wwwexampleIdp.com/saml",
          IsPassive: "true",
        },
        "saml:Issuer": [
          {
            _: "http://exampleSp.com/saml",
            $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              Format: "alternateIdentifier",
              AllowCreate: "true",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: { "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol", Comparison: "exact" },
            "saml:AuthnContextClassRef": [
              {
                _: "myAuthnContext",
                $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
              },
              {
                _: "myAuthnContext2",
                $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
              },
            ],
          },
        ],
      },
    },
  },
  {
    name: "Config with ProviderName",
    config: {
      issuer: "http://exampleSp.com/saml",
      identifierFormat: "alternateIdentifier",
      providerName: "myProviderName",
      cert: FAKE_CERT,
    },
    result: {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          ProviderName: "myProviderName",
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          Destination: "https://wwwexampleIdp.com/saml",
        },
        "saml:Issuer": [
          {
            _: "http://exampleSp.com/saml",
            $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              Format: "alternateIdentifier",
              AllowCreate: "true",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: { "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol", Comparison: "exact" },
            "saml:AuthnContextClassRef": [
              {
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
              },
            ],
          },
        ],
      },
    },
  },
  {
    name: "Remove NameIDPolicy, AuthnRequest, and AssertionConsumerServiceURL Config",
    config: {
      identifierFormat: null,
      disableRequestedAuthnContext: true,
      disableRequestAcsUrl: true,
      cert: FAKE_CERT,
    },
    result: {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          Destination: "https://wwwexampleIdp.com/saml",
        },
        "saml:Issuer": [
          { _: "onelogin_saml", $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" } },
        ],
      },
    },
  },
  {
    name: "Config with full Scoping config",
    config: {
      issuer: "http://exampleSp.com/saml",
      identifierFormat: "alternateIdentifier",
      scoping: {
        proxyCount: 2,
        requesterId: "fooBarRequesterId",
        idpList: [
          {
            entries: [
              {
                providerId: "myScopingProviderId",
                name: "myScopingProviderName",
                loc: "myScopingProviderLoc",
              },
            ],
            getComplete: "https://www.getcompleteidplist.com",
          },
        ],
      },
      cert: FAKE_CERT,
    },
    result: {
      "samlp:AuthnRequest": {
        $: {
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          Destination: "https://wwwexampleIdp.com/saml",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          Version: "2.0",
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        },
        "saml:Issuer": [
          {
            $: {
              "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            },
            _: "http://exampleSp.com/saml",
          },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              AllowCreate: "true",
              Format: "alternateIdentifier",
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: {
              Comparison: "exact",
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
            "saml:AuthnContextClassRef": [
              {
                $: {
                  "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
                },
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
              },
            ],
          },
        ],
        "samlp:Scoping": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              ProxyCount: "2",
            },
            "samlp:IDPList": [
              {
                $: {
                  "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                },
                "samlp:GetComplete": ["https://www.getcompleteidplist.com"],
                "samlp:IDPEntry": [
                  {
                    $: {
                      Loc: "myScopingProviderLoc",
                      Name: "myScopingProviderName",
                      ProviderID: "myScopingProviderId",
                      "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                    },
                  },
                ],
              },
            ],
            "samlp:RequesterID": ["fooBarRequesterId"],
          },
        ],
      },
    },
  },
  {
    name: "Config with Scoping config without proxyCount and requesterId",
    config: {
      issuer: "http://exampleSp.com/saml",
      identifierFormat: "alternateIdentifier",
      scoping: {
        idpList: [
          {
            entries: [
              {
                providerId: "myScopingProviderId",
                name: "myScopingProviderName",
                loc: "myScopingProviderLoc",
              },
            ],
            getComplete: "https://www.getcompleteidplist.com",
          },
        ],
      },
      cert: FAKE_CERT,
    },
    result: {
      "samlp:AuthnRequest": {
        $: {
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          Destination: "https://wwwexampleIdp.com/saml",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          Version: "2.0",
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        },
        "saml:Issuer": [
          {
            $: {
              "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            },
            _: "http://exampleSp.com/saml",
          },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              AllowCreate: "true",
              Format: "alternateIdentifier",
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: {
              Comparison: "exact",
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
            "saml:AuthnContextClassRef": [
              {
                $: {
                  "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
                },
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
              },
            ],
          },
        ],
        "samlp:Scoping": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
            "samlp:IDPList": [
              {
                $: {
                  "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                },
                "samlp:GetComplete": ["https://www.getcompleteidplist.com"],
                "samlp:IDPEntry": [
                  {
                    $: {
                      Loc: "myScopingProviderLoc",
                      Name: "myScopingProviderName",
                      ProviderID: "myScopingProviderId",
                      "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                    },
                  },
                ],
              },
            ],
          },
        ],
      },
    },
  },
  {
    name: "Config with Scoping config without proxyCount, requesterId, getComplete",
    config: {
      issuer: "http://exampleSp.com/saml",
      identifierFormat: "alternateIdentifier",
      scoping: {
        idpList: [
          {
            entries: [
              {
                providerId: "myScopingProviderId",
                name: "myScopingProviderName",
                loc: "myScopingProviderLoc",
              },
            ],
          },
        ],
      },
      cert: FAKE_CERT,
    },
    result: {
      "samlp:AuthnRequest": {
        $: {
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          Destination: "https://wwwexampleIdp.com/saml",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          Version: "2.0",
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        },
        "saml:Issuer": [
          {
            $: {
              "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            },
            _: "http://exampleSp.com/saml",
          },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              AllowCreate: "true",
              Format: "alternateIdentifier",
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: {
              Comparison: "exact",
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
            "saml:AuthnContextClassRef": [
              {
                $: {
                  "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
                },
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
              },
            ],
          },
        ],
        "samlp:Scoping": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
            "samlp:IDPList": [
              {
                $: {
                  "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                },
                "samlp:IDPEntry": [
                  {
                    $: {
                      Loc: "myScopingProviderLoc",
                      Name: "myScopingProviderName",
                      ProviderID: "myScopingProviderId",
                      "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                    },
                  },
                ],
              },
            ],
          },
        ],
      },
    },
  },
  {
    name: "Config with Scoping config without proxyCount, requesterId, idpList getComplete, entry name, entry loc",
    config: {
      issuer: "http://exampleSp.com/saml",
      identifierFormat: "alternateIdentifier",
      scoping: {
        idpList: [
          {
            entries: [
              {
                providerId: "myScopingProviderId",
              },
            ],
          },
        ],
      },
      cert: FAKE_CERT,
    },
    result: {
      "samlp:AuthnRequest": {
        $: {
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          Destination: "https://wwwexampleIdp.com/saml",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          Version: "2.0",
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        },
        "saml:Issuer": [
          {
            $: {
              "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            },
            _: "http://exampleSp.com/saml",
          },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              AllowCreate: "true",
              Format: "alternateIdentifier",
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: {
              Comparison: "exact",
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
            "saml:AuthnContextClassRef": [
              {
                $: {
                  "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
                },
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
              },
            ],
          },
        ],
        "samlp:Scoping": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
            "samlp:IDPList": [
              {
                $: {
                  "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                },
                "samlp:IDPEntry": [
                  {
                    $: {
                      ProviderID: "myScopingProviderId",
                      "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                    },
                  },
                ],
              },
            ],
          },
        ],
      },
    },
  },
  {
    name: "Config with Scoping and multiple IDPList entries",
    config: {
      issuer: "http://exampleSp.com/saml",
      identifierFormat: "alternateIdentifier",
      scoping: {
        idpList: [
          {
            entries: [
              {
                providerId: "myScopingProviderId",
              },
              {
                providerId: "myOtherScopingProviderId",
              },
            ],
          },
        ],
      },
      cert: FAKE_CERT,
    },
    result: {
      "samlp:AuthnRequest": {
        $: {
          AssertionConsumerServiceURL: "http://localhost:3033/login",
          Destination: "https://wwwexampleIdp.com/saml",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          Version: "2.0",
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        },
        "saml:Issuer": [
          {
            $: {
              "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            },
            _: "http://exampleSp.com/saml",
          },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              AllowCreate: "true",
              Format: "alternateIdentifier",
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: {
              Comparison: "exact",
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
            "saml:AuthnContextClassRef": [
              {
                $: {
                  "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
                },
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
              },
            ],
          },
        ],
        "samlp:Scoping": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
            "samlp:IDPList": [
              {
                $: {
                  "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                },
                "samlp:IDPEntry": [
                  {
                    $: {
                      ProviderID: "myScopingProviderId",
                      "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                    },
                  },
                  {
                    $: {
                      ProviderID: "myOtherScopingProviderId",
                      "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                    },
                  },
                ],
              },
            ],
          },
        ],
      },
    },
  },
];

export const logoutChecks: CapturedCheck[] = [
  {
    name: "Logout",
    config: {
      skipRequestCompression: true,
      entryPoint: "https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO",
      cert: fs.readFileSync(__dirname + "/static/cert.pem", "ascii"),
      identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    },
    samlRequest: {
      SAMLRequest: fs.readFileSync(
        __dirname + "/static/logout_request_with_good_signature.xml",
        "base64"
      ),
    },
    expectedStatusCode: 200,
    mockDate: "2014-06-02T17:48:56.820Z",
    result: {
      "samlp:LogoutResponse": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
          Version: "2.0",
          Destination: "https://wwwexampleIdp.com/saml",
          InResponseTo: "pfxd4d369e8-9ea1-780c-aff8-a1d11a9862a1",
        },
        "saml:Issuer": ["onelogin_saml"],
        "samlp:Status": [
          {
            "samlp:StatusCode": [
              {
                $: {
                  Value: "urn:oasis:names:tc:SAML:2.0:status:Requester",
                },
                "samlp:StatusCode": [
                  {
                    $: {
                      Value: "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
                    },
                  },
                ],
              },
            ],
          },
        ],
      },
    },
  },
];

describe("captured SAML requests /", function () {
  let server: Server;

  function testForCheck(check: SamlCheck) {
    return function (done: Mocha.Done) {
      const app = express();
      try {
        app.use(bodyParser.urlencoded({ extended: false }));
        app.use(passport.initialize());
        const config = check.config;
        config.callbackUrl = "http://localhost:3033/login";
        config.entryPoint = "https://wwwexampleIdp.com/saml";
        let profile: Profile;
        const strategy = new SamlStrategy(config, function (
          _profile: Profile | null,
          done: VerifiedCallback
        ) {
          if (_profile) {
            profile = _profile;
            done(null, profile);
          }
        });
        passport.use(strategy);

        let userSerialized = false;
        passport.serializeUser(function (user, done) {
          userSerialized = true;
          done(null, user);
        });
      } catch (err) {
        done(err);
      }

      app.get(
        "/login",
        passport.authenticate("saml", {
          samlFallback: "login-request",
          session: false,
        } as AuthenticateOptions),
        function (req, res) {
          res.status(200).send("200 OK");
        }
      );

      app.use(function (
        err: Error | null,
        req: express.Request,
        res: express.Response,
        next: express.NextFunction
      ) {
        if (err) {
          done(err);
          res.status(500).send("500 Internal Server Error");
        }
      });

      server = app.listen(3033, function () {
        const requestOpts = {
          url: "http://localhost:3033/login",
          method: "get",
          followRedirect: false,
        };

        function helper(err: Error | null, samlRequest: Buffer) {
          try {
            should.not.exist(err);
            parseString(samlRequest.toString(), function (err, doc) {
              try {
                should.not.exist(err);
                delete doc["samlp:AuthnRequest"]["$"]["ID"];
                delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
                doc.should.eql(check.result);
                done();
              } catch (err2) {
                done(err2);
              }
            });
          } catch (err3) {
            done(err3);
          }
        }

        // TODO remove usage of request module
        request(requestOpts, function (err: Error | null, response: any, body: any) {
          try {
            should.not.exist(err);

            let encodedSamlRequest;
            if (check.config.authnRequestBinding === "HTTP-POST") {
              response.statusCode.should.equal(200);
              body.should.match(/<!DOCTYPE html>[^]*<input.*name="SAMLRequest"[^]*<\/html>/);
              encodedSamlRequest = body.match(/<input.*name="SAMLRequest" value="([^"]*)"/)[1];
            } else {
              response.statusCode.should.equal(302);
              const query = response.headers.location.match(/^[^?]*\?(.*)$/)[1];
              encodedSamlRequest = querystring.parse(query).SAMLRequest;
            }

            const buffer = Buffer.from(encodedSamlRequest, "base64");
            if (check.config.skipRequestCompression) helper(null, buffer);
            else zlib.inflateRaw(buffer, helper);
          } catch (err2) {
            done(err2);
          }
        });
      });
    };
  }

  function testForCheckLogout(check: CapturedCheck) {
    return function (done: Mocha.Done) {
      const app = express();
      app.use(bodyParser.urlencoded({ extended: false }));
      app.use(passport.initialize());
      const config = check.config;
      config.callbackUrl = "http://localhost:3033/login";
      config.entryPoint = "https://wwwexampleIdp.com/saml";
      let profile: Profile;
      const strategy = new SamlStrategy(config, function (
        _profile: Profile | null,
        done: VerifiedCallback
      ) {
        if (_profile) {
          profile = _profile;
          done(null, profile);
        }
      });

      passport.use(strategy);

      app.post("/logout", passport.authenticate("saml"), function (req, res) {
        res.status(200).send("200 OK");
      });

      app.use(function (
        err: Error,
        req: express.Request,
        res: express.Response,
        next: express.NextFunction
      ) {
        if (err) {
          done(err);
          res.status(500).send("500 Internal Server Error");
        }
      });

      server = app.listen(3033, function () {
        const requestOpts = {
          url: "http://localhost:3033/logout",
          method: "post",
          form: check.samlRequest,
        };

        function helper(err: Error | null, samlResponse: any) {
          try {
            should.not.exist(err);
            parseString(samlResponse.toString(), function (err, doc) {
              try {
                should.not.exist(err);
                delete doc["samlp:LogoutResponse"]["$"]["ID"];
                delete doc["samlp:LogoutResponse"]["$"]["IssueInstant"];
                doc.should.eql(check.result);
                done();
              } catch (err2) {
                done(err2);
              }
            });
          } catch (err2) {
            done(err2);
          }
        }

        // TODO remove usage of request module
        request(requestOpts, function (this: any, err: any, response: any, body: any) {
          try {
            const encodedSamlResponse = querystring.parse(this.uri.query).SAMLResponse;
            // An error will exist because the endpoint we're trying to log out of doesn't exist,
            // but we can still test to make sure that everything is behaving as it should.
            // should.not.exist(err);

            const buffer = Buffer.from(encodedSamlResponse as string, "base64");
            if (check.config.skipRequestCompression) helper(null, buffer);
            else zlib.inflateRaw(buffer, helper);
          } catch (err2) {
            done(err2);
          }
        });
      });
    };
  }

  for (let i = 0; i < capturedSamlRequestChecks.length; i++) {
    const check = capturedSamlRequestChecks[i];
    it(check.name, testForCheck(check));
  }

  for (let i = 0; i < logoutChecks.length; i++) {
    const check = logoutChecks[i];
    it(check.name, testForCheckLogout(check));
  }

  afterEach(function (done) {
    server.close(done);
  });
});
