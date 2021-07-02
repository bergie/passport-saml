"use strict";

import * as sinon from "sinon";
import { Profile, SAML, Strategy as SamlStrategy } from "../src";
import { RequestWithUser, VerifiedCallback } from "../src/types";
import { FAKE_CERT } from "./types";

const noop = () => undefined;

describe("strategy#authorize", function () {
  let getAuthorizeFormStub: sinon.SinonStub;
  let getAuthorizeUrlStub: sinon.SinonStub;
  let getLogoutResponseUrl: sinon.SinonStub;
  let validatePostResponseAsync: sinon.SinonStub;
  let errorStub: sinon.SinonStub;
  let redirectStub: sinon.SinonStub;
  let requestWithUser = {} as unknown as RequestWithUser;
  let requestWithUserPostResponse = {} as unknown as RequestWithUser;

  beforeEach(function () {
    getAuthorizeFormStub = sinon.stub(SAML.prototype, "getAuthorizeFormAsync").resolves();
    getAuthorizeUrlStub = sinon.stub(SAML.prototype, "getAuthorizeUrlAsync").resolves();
    getLogoutResponseUrl = sinon.stub(SAML.prototype, "getLogoutResponseUrl");
    validatePostResponseAsync = sinon.stub(SAML.prototype, "validatePostResponseAsync");
    errorStub = sinon.stub(SamlStrategy.prototype, "error");
    redirectStub = sinon.stub(SamlStrategy.prototype, "redirect");

    requestWithUser = {
      logout: noop,
      res: { send: noop },
    } as unknown as RequestWithUser;
    requestWithUserPostResponse = {
      body: { SAMLResponse: {} },
      logout: noop,
      res: { send: noop },
    } as unknown as RequestWithUser;
  });

  afterEach(function () {
    getAuthorizeFormStub.restore();
    getAuthorizeUrlStub.restore();
    getLogoutResponseUrl.restore();
    validatePostResponseAsync.restore();
    errorStub.restore();
    redirectStub.restore();
  });

  it("calls getAuthorizeForm when authnRequestBinding is HTTP-POST", function (done) {
    const strategy = new SamlStrategy(
      {
        authnRequestBinding: "HTTP-POST",
        cert: FAKE_CERT,
      },
      noop
    );

    // This returns immediately, but calls async functions; need to turn event loop
    strategy.authenticate(requestWithUser, {});

    setImmediate(() => {
      sinon.assert.notCalled(errorStub);
      sinon.assert.calledOnce(getAuthorizeFormStub);
      done();
    });
  });

  it("calls getAuthorizeUrl when authnRequestBinding is not HTTP-POST", function (done) {
    const strategy = new SamlStrategy({ cert: FAKE_CERT }, noop);

    // This returns immediately, but calls async functions; need to turn event loop
    strategy.authenticate(requestWithUser, {});

    setImmediate(() => {
      sinon.assert.notCalled(errorStub);
      sinon.assert.calledOnce(getAuthorizeUrlStub);
      sinon.assert.calledOnce(redirectStub);
      done();
    });
  });

  it("determines that logout was unsuccessful where user doesn't match", function (done) {
    const strategy = new SamlStrategy({ cert: FAKE_CERT }, function (
      _profile: Profile | null,
      done: VerifiedCallback
    ) {
      if (_profile) {
        done(null, { name: _profile.nameID });
      }
    });

    validatePostResponseAsync.resolves({
      profile: {
        ID: "ID",
        issuer: "issuer",
        nameID: "some other user",
        nameIDFormat: "nameIDFormat",
      },
      loggedOut: true,
    });

    // Pretend we already loaded a users session from a cookie or something
    // by calling `strategy.authenticate` when the request comes in
    requestWithUserPostResponse.user = {
      name: "some user",
    };

    // This returns immediately, but calls async functions; need to turn event loop
    strategy.authenticate(requestWithUserPostResponse, {});

    setImmediate(() => {
      sinon.assert.notCalled(errorStub);
      sinon.assert.calledOnceWithMatch(
        getLogoutResponseUrl,
        sinon.match.any,
        sinon.match.any,
        sinon.match.any,
        false,
        sinon.match.func
      );
      done();
    });
  });

  it("determines that logout was successful where user matches", function (done) {
    const strategy = new SamlStrategy({ cert: FAKE_CERT }, function (
      _profile: Profile | null,
      done: VerifiedCallback
    ) {
      if (_profile) {
        done(null, { name: _profile.nameID });
      }
    });

    validatePostResponseAsync.resolves({
      profile: {
        ID: "ID",
        issuer: "issuer",
        nameID: "some user",
        nameIDFormat: "nameIDFormat",
      },
      loggedOut: true,
    });

    // Pretend we already loaded a users session from a cookie or something
    // by calling `strategy.authenticate` when the request comes in
    requestWithUserPostResponse.user = {
      name: "some user",
    };

    // This returns immediately, but calls async functions; need to turn event loop
    strategy.authenticate(requestWithUserPostResponse, {});

    setImmediate(() => {
      sinon.assert.notCalled(errorStub);
      sinon.assert.calledOnceWithMatch(
        getLogoutResponseUrl,
        sinon.match.any,
        sinon.match.any,
        sinon.match.any,
        true,
        sinon.match.func
      );
      done();
    });
  });
});
