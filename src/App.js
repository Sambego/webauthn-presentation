import React, { Component } from "react";
import {
  Deck,
  Slide,
  Title,
  Subtitle,
  Image,
  Columns,
  List,
  Text,
  Browser,
  Code,
  Video,
  Highlight,
  Footer,
} from "@sambego/diorama";

import AnnoyingForm from "./Components/Annoying";
import Webauthn from "./Components/Webauthn";

import Sam from "./img/sam.png";
import NPM from "./video/npm.mp4";
import Poes from "./img/poes.jpg";
import Pattern from "./img/pattern.png";
import Pattern2 from "./img/pattern-2.png";
import IOSOtp from "./img/iOS-otp.png";
import Magic from "./img/magic-link.png";
import GoogleAuthenticator from "./img/google-authenticator.png";
import Social from "./img/social.png";
import AUthenticators from "./img/authenticators.jpg";
import FastForward from "./img/fast-forward.svg";
import BreachedPW from "./img/breached-pw.png";
import Checkup from "./img/checkup2.png";
import Guardian from "./img/guardian.png";
import GoogleAuthenticatorExp from "./img/google-authenticator-exp.png";
import Webauthn1 from "./img/webauthn-1.svg";
import Webauthn2 from "./img/webauthn-2.svg";
import Webauthn3 from "./img/webauthn-3.svg";
import Webauthn4 from "./img/webauthn-4.svg";
import Webauthn5 from "./img/webauthn-5.svg";
import Webauthn6 from "./img/webauthn-6.svg";
import Webauthn7 from "./img/webauthn-7.svg";
import Webauthn8 from "./img/webauthn-8.svg";
import Webauthn9 from "./img/webauthn-9.svg";
import Webauthn10 from "./img/webauthn-10.svg";
import cc from "./img/cc.svg";
import IOSReg from "./img/IOS-reg.png";
import IOSLogin from "./img/IOS-login.png";
import ChromeManageCreds from "./img/chrome-manage-creds.png";
import YubicoManager from "./img/yubico-manager.png";
import Joel from "./img/joel.jpg";
import Debugger from "./img/debugger.png";
import Auth0Webauthn1 from "./img/Auth0-webauthn-1.png";
import Auth0Webauthn2 from "./img/Auth0-webauthn-2.png";
import Auth0Webauthn3 from "./img/Auth0-webauthn-3.png";
import Auth0CredentialGuard from "./img/credential-guard.png";
import Push1 from "./img/push1.png";
import Push2 from "./img/push2.png";

import biometric from "./video/biometric.mp4";

class App extends Component {
  render() {
    const code1 =
      "navigator.credentials.create({\n  publicKey: {\n    ...\n  }\n});";
    const code2 =
      "publicKey: {\n  ...\n  challenge: Uint8Array([1, 2, ... 3, 4]),\n  ...\n }";
    const code3 =
      "publicKey: {\n  ...\n  rp: {\n    id: 'sambego.tech'\n    name: 'Sambego'\n  },\n  ...\n }";
    const code4 =
      "publicKey: {\n  ...\n  user: {\n    id: Uint8Array([1, 2, ... 3, 4]),\n    name: 'Sam Bellen',\n    displayName: 'Sambego'\n  },\n  ...\n }";
    const codePubKeyCred =
      "publicKey: {\n  ...\n  pubKeyCredParams: [\n    {  \n      type: 'public-key',\n      alg: -7,\n    }\n  ],\n  ...\n }";
    const codeTimeout = "publicKey: {\n  ...\n  timeout: 15000,\n  ...\n }";
    const codeExclude =
      "publicKey: {\n  ...\n  excludeCredentials: [\n    {\n      type: 'public-key',\n      id: Uint8Array([4, 3, ... 2, 1]),\n      transports: ['USB', 'NFC', 'BLE', 'internal']\n    },\n  ...\n }";
    const code5 =
      "publicKey: {\n  ...\n  authenticatorSelection: {  \n    authenticatorAttachment: 'platform',\n    userVerification: 'preferred'\n    requireResidentKey: true,\n  },\n  ...\n }";
    const code6 = "publicKey: {\n  ...\n  attestation: 'direct',\n  ...\n }";
    const code7 =
      "navigator.credentials.get({\n  publicKey: {\n    ...\n  }\n});";
    const code8 = "const getConfig = {\n  publicKey: {\n    ...\n  }\n}";
    const code9 =
      "publicKey: {\n  ...\n  challenge: Uint8Array([1, 2, ... 3, 4]),\n  ...\n}";
    const code10 =
      "publicKey: {\n  ...\n  allowCredentials: [\n    {\n      type: 'public-key',\n      id: Uint8Array([1, 2, ... 3, 4]),\n      transports: ['USB', 'NFC', 'BLE']\n    }\n  ],\n  ...\n}";
    const code11 =
      "publicKey: {\n  ...\n  userVerification: 'preferred',\n  ...\n}";
    const resCredcode =
      "publicKey: {\n  ...\n  authenticatorSelection: {  \n    ...\n    requireResidentKey: true\n  },\n  ...\n }";
    const isAvailableCode =
      "PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();";
      const createBackend1 = "{\n  \"rawId\": \"010d...8c\",\n  \"id\": \"AQ...ow\",\n  \"type\": \"public-key\",\n  \"response\": {\n    \"clientDataJSON\": {...},\n    \"attestationObject\": {...}\n  }\n}";
      const createBackend2 = "{\n  \"clientDataJSON\": {\n    \"type\": \"webauthn.create\",\n    \"challenge\": \"FuRfP7QOl...RiHq3iytg\",\n    \"origin\": \"https://webauthn.me\",\n    \"crossOrigin\": false,\n  }\n}";
      const createBackend3 = "{\n  \"attestationObject\": {\n    \"fmt\": \"none\",\n    \"attStmt\": {...},\n    \"authData\": {\n      \"rpIdHash\": \"f9...ad\",\n      \"flags\": {...},\n      \"attestedCredentialData\": {\n        \"credentialPublicKey\": {\n          \"kty\": \"EC\",\n          \"alg\": \"ECDSA_w_SHA256\",\n          \"crv\": \"P-256\",\n          \"x\": \"ig...JvGg=\",\n          \"y\": \"PK...06c4=\"\n        }\n      }\n    }\n  }\n}";
      const getBackend = "{\n  \"signature\": \"304...85c\",\n  \"userHandle\": \"5b4...d98\",\n  \"clientDataJSON\": {\n    \"type\": \"webauthn.get\",\n    \"challenge\": \"FuRfP7QOlAWW6moq2oU4MR9Mlxi6pJ3LqJRiHq3iytg\",\n    \"origin\": \"https://webauthn.me\",\n    \"crossOrigin\": false\n  },\n  \"authenticatorData\": {\n    \"rpIdHash\": \"f95...cd2e1ad\",\n    \"signCount\": 1600698991\n  }\n}";
    // const footer = <Footer left="@sambego" right="1990.sambego.tech&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" />
    const footer = <Footer left={<Highlight style={{background: "#6699CC"}}>@sambego</Highlight>} right={<Highlight style={{background: "#6699CC"}}>webauthn.sambego.tech</Highlight>} />;
    
    return (
      // <Deck navigation footer={footer}>
      <Deck footer={footer} presenterNotes>
      {/* <Deck footer={footer} > */}
        <Slide style={{ background: "#6699CC", color: "#fff" }}>
          <Video
            src={biometric}
            loop
            autoplay
            full
            color="#6699CC"
            style={{ overflow: "hidden", zIndex: 1 }}
          />
          <Title style={{ color: "#ffffff", position: "relative", zIndex: 1, textShadow: '-4px -4px 0 #6699CC,4px -4px 0 #6699CC,-4px 4px 0 #6699CC,4px 4px 0 #6699CC'}}>
            WebAuthN
          </Title>
          <Subtitle style={{ 
            color: "#ffffff", 
            position: "relative", 
            zIndex: 1, 
            fontSize: '1.6vw', 
            borderTop: '1px solid #fff', 
            paddingTop: '2rem', 
            textShadow: '-2px -2px 0 #6699CC,2px -2px 0 #6699CC,-2px 2px 0 #6699CC,2px 2px 0 #6699CC',
          }}>Protecting digital identities with physical Authenticator devices</Subtitle>
          <Image
            src={cc}
            style={{
              position: "fixed",
              bottom: "2rem",
              left: "2rem",
              width: "10%",
              zIndex: 2,
            }}
            alt="Creative commons"
          />
        </Slide>
        <Slide>
          <Columns>
            <div>
              <Image src={Sam} alt="A picture of me" full color="#6699CC" />
            </div>
            <div>
              <Subtitle>Sam Bellen</Subtitle>
              <List>
                <li>Developer Advocate Engineer</li>
                <li>Auth0</li>
                <li>Google Developer Expert</li>
                <li>@sambego</li>
              </List>
            </div>
          </Columns>
        </Slide>
        {/* <Slide>
          <video src={NPM} autoPlay style={{ height: "80vh" }}></video>
          <Text>
            <span style={{ fontFamily: "monospace" }}>
              npx @sambego/about-me
            </span>
          </Text>
        </Slide> */}
        <Slide>
          <Subtitle>
            <a
              style={{ color: "#000", borderColor: "#6699CC" }}
              href="https://webauthn.sambego.tech"
            >
              webauthn.sambego.tech
            </a>
          </Subtitle>
        </Slide>
        <Slide>
          <List>
            <Subtitle style={{ display: "inline-block" }}>Summary</Subtitle>
            <li>WebAuth-<Highlight style={{background: "#6699CC", fontWeight: 'bold'}}>what</Highlight>?</li>
            <li>WebAuth-<Highlight style={{background: "#6699CC", fontWeight: 'bold'}}>why</Highlight>?</li>
            <li>WebAuth-<Highlight style={{background: "#6699CC", fontWeight: 'bold'}}>how</Highlight>?</li>
            
          </List>
        </Slide>

        
        <Slide style={{ background: "#6699CC"}}>
          <Title>WebAuth-<Highlight style={{background: "#fff"}}>what</Highlight>?</Title>
        </Slide>
        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>Web Authentication</Highlight> API</Subtitle>
        </Slide>
        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>WebAuthN</Highlight></Subtitle>
        </Slide>
        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>Key based</Highlight> authentication</Subtitle>
        </Slide>
        <Slide>
          <Subtitle>Requires a <Highlight style={{background: "#6699CC"}}>user interaction</Highlight></Subtitle>
        </Slide>
        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>Hardware</Highlight> authenticator</Subtitle>
        </Slide>
        <Slide>
          <Image src={AUthenticators} alt="USB Authenticator" />
        </Slide>
        <Slide>
          <List>
            <li>USB</li>
            <li>Lightning</li>
            <li>Bluetooth Low Energy</li>
            <li>NFC</li>
          </List>
        </Slide>
        <Slide>
          <Subtitle>Who has one?</Subtitle>
        </Slide>
        <Slide>
          <Subtitle>
            Most modern devices have a <Highlight style={{background: "#6699CC"}}>built in authenticator device</Highlight>
          </Subtitle>
        </Slide>

        <Slide style={{ background: "#6699CC"}}>
          <Title>WebAuth-<Highlight style={{background: "#ffffff"}}>why</Highlight>?</Title>
        </Slide>
        <Slide>
          <AnnoyingForm />
        </Slide>
        <Slide>
          <Subtitle style={{ fontSize: "20rem" }}>🤬</Subtitle>
        </Slide>
        <Slide>
          <Subtitle>Passwords can be <Highlight style={{background: "#6699CC"}}>annoying</Highlight>!</Subtitle>
        </Slide>
        <Slide>
          <Subtitle>Passwords can be <Highlight style={{background: "#6699CC"}}>insecure</Highlight>!</Subtitle>
        </Slide>
        <Slide>
          <Subtitle>Passwords can be <Highlight style={{background: "#6699CC"}}>stolen</Highlight>!</Subtitle>
        </Slide>
        
        <Slide>
          <Webauthn platform />
        </Slide>
        <Slide>
          <Subtitle style={{ fontSize: "20rem" }}>🎉</Subtitle>
        </Slide>


        <Slide style={{ background: "#6699CC"}}>
          <Title>WebAuth-<Highlight style={{background: "#ffffff"}}>how</Highlight>?</Title>
        </Slide>
        <Slide>
          <Subtitle>We first need to <Highlight style={{background: "#6699CC"}}>create new credentials</Highlight></Subtitle>
        </Slide>
        <Slide>
          <Image src={Webauthn1} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Image src={Webauthn2} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Image src={Webauthn3} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Image src={Webauthn4} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Image src={Webauthn5} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Image src={Webauthn6} alt="Webauthn schema" />
        </Slide>

        <Slide>
          <Subtitle>Once registered, we can <Highlight style={{background: "#6699CC"}}>authenticate</Highlight></Subtitle>
        </Slide>
        <Slide>
          <Image src={Webauthn1} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Image src={Webauthn7} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Image src={Webauthn8} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Image src={Webauthn4} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Image src={Webauthn9} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Image src={Webauthn10} alt="Webauthn schema" />
        </Slide>

        <Slide>
          <Subtitle>Let's look at some <Highlight style={{background: "#6699CC"}}>code</Highlight></Subtitle>
        </Slide>
        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>Create</Highlight> new credentials</Subtitle>
        </Slide>
        <Slide>
          <Code code={code1} />
        </Slide>
        <Slide notes="The challenge is a buffer of randomly generated bytes with a minimum of 16 bytes. This is generated on the server using a cryptographically secure random number generator. By generating the challenge on the server we can prevent 'replay attacks'. The authenticator will sign this along with other data.">
          <Code code={code2} />
        </Slide>
        <Slide notes="This is the entity which is responsible for handling all things authentication, usually your authorization server or identity provider (IdP). The id must be the current domain or a subset of it. The name is used to describe the relying party.">
          <Code code={code3} />
        </Slide>
        <Slide notes="The user object contains profile information about the user like its name and preferred display name. It also contains a user id which is again a buffer with byte values. To ensure secure operation, authentication and authorization decisions must be made based on this user id, not the name or display name. The user id can not contain information that can identify a user, like a username or an email.">
          <Code code={code4} />
        </Slide>
        <Slide notes="This is a collection of accepted public key types. The algorithm (alg) is a number that references a key type in this list of COSE algorithms.">
          <Code code={codePubKeyCred} />
          <p style={{ marginTop: "3rem", fontSize: "3rem" }}>
            <a
              href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms"
              target="_blank"
              style={{ color: "#000", borderColor: "#6699CC" }}
            >
              https://www.iana.org/assignments/cose/cose.xhtml#algorithms
            </a>
          </p>
        </Slide>
        <Slide notes="Defines the maximum time in milliseconds the user has to complete the registration action. This can be touching their authenticator device, TouchID or any other method used to interact with an authenticator.">
          <Code code={codeTimeout} />
        </Slide>
        <Slide notes="You can use this if you wish to limit the creation of multiple credentials for the same account on a single authenticator. Your browser will throw an error if you try to create a new credential while one of the public keys in this collection already exists on the authenticator.">
          <Code code={codeExclude} />
        </Slide>
        <Slide notes="You can limit the type of authenticator devices you allow to register new credentials with part of the configuration.    Authenticator Attachment  Only allow platform authenticators like TouchID or Windows Hello. You can also do the opposite, and only allow cross-platform authenticators like a Yubikey or a Google Titan Security Key.    Require Resident Key  When set to true, the private key is stored on the authenticator. This means that the user can login without entering a username. This can be done with the user.id property we’ve seen before. The relying party will create a user handle which is stored in the resident key on the authenticator when creating a new credential. When authenticating the authenticator will return the user handle, so the relying party can look up the user linked to this user handle.    User Verification  Use the user verification option to only allow or discourage authenticators that verify the user is performing the registration. By checking a fingerprint with TouchID or doing facial recognition with Windows Hello the authenticator can verify the user performing the registration.">
          <Code code={code5} />
        </Slide>
        <Slide notes="An attestation object is returned when completing the registration. With this parameter, you can specify if you want the attestation data from the authenticator as is (direct), or you're fine with anonymized (indirect) data.">
          <Code code={code6} />
        </Slide>

        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>Use</Highlight> the created credentials</Subtitle>
        </Slide>
        <Slide>
          <Code code={code7} />
        </Slide>
        <Slide>
          <Code code={code9} />
        </Slide>
        <Slide>
          <Code code={code10} />
        </Slide>
        <Slide>
          <Code code={code11} />
        </Slide>

        <Slide>
          <Subtitle>What to do on the <Highlight style={{background: "#6699CC"}}>backend</Highlight>?</Subtitle>
        </Slide>
        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>Creating</Highlight> a new credential</Subtitle>
        </Slide>
        <Slide>
          <Code code={createBackend1} />
        </Slide>
        <Slide><Subtitle>The Client Data JSON Object is a <Highlight style={{background: "#6699CC"}}>JSON string</Highlight> as an <Highlight style={{background: "#6699CC"}}>ArrayBuffer</Highlight></Subtitle></Slide>
        <Slide>
          <Code code={createBackend2} />
        </Slide>
        <Slide notes="Concise Binary Object Representation"><Subtitle>The attestation Object is a <Highlight style={{background: "#6699CC"}}>CBOR encoded ArrayBuffer</Highlight></Subtitle></Slide>
        <Slide notes="attStmt: lets call it the signature, Flags contain more info like was the user preset, was the user verified">
          <Code code={createBackend3} />
        </Slide>
        <Slide><Subtitle>Validate the returned authenticator data. <br/><br/><Highlight style={{background: "#6699CC"}}>Is there an ID? </Highlight></Subtitle></Slide>
        <Slide><Subtitle>Validate the returned client data. <br/><br/><Highlight style={{background: "#6699CC"}}>Challenge, Origin, ...</Highlight></Subtitle></Slide>
        <Slide><Subtitle>Validate the returned attestation data <br/><br/><Highlight style={{background: "#6699CC"}}>User verified, ...</Highlight></Subtitle></Slide>
        <Slide><Subtitle>Save the <Highlight style={{background: "#6699CC"}}>credential ID</Highlight> and <Highlight style={{background: "#6699CC"}}>pulic key</Highlight> data</Subtitle></Slide>

        <Slide><Subtitle>When <Highlight style={{background: "#6699CC"}}>verifying</Highlight> an existing credential</Subtitle></Slide>
        <Slide>
          <Code code={getBackend} />
        </Slide>
        <Slide><Subtitle>Validate <Highlight style={{background: "#6699CC"}}>user, challenge, and origin</Highlight></Subtitle></Slide>
        <Slide><Subtitle>Validate the returned <Highlight style={{background: "#6699CC"}}>signature</Highlight></Subtitle></Slide>
        
        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>Resident</Highlight> credentials</Subtitle>
        </Slide>
        <Slide>
          <Code code={resCredcode} />
        </Slide>
        {/* <Slide>
          <Webauthn resident/>
        </Slide> */}
        
        
        {/* <Slide>
          <Image contain src={Debugger} alt="Chrome devtools WebAuthn debugger" />
        </Slide> */}
        <Slide>
          <List>
            <li>
              <a href="https://webauthn.me/debugger" target="_blank" style={{ color: "#000", borderColor: "#6699CC" }}>
                https://webauthn.me/debugger
              </a>
            </li>
          </List>
        </Slide>

        <Slide>
          <Subtitle>What are the <Highlight style={{background: "#6699CC"}}>benefits</Highlight> of WebAuthn</Subtitle>
        </Slide>
        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>Private/Public Key</Highlight> based authentication</Subtitle>
        </Slide>
        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>Phishing</Highlight> resistant</Subtitle>
        </Slide>
        <Slide>
          <Subtitle>You only <Highlight style={{background: "#6699CC"}}>store public data</Highlight> in you database</Subtitle>
        </Slide>
        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>Fine-grained controll</Highlight> which kind of credentials to allow</Subtitle>
        </Slide>
        <Slide>
          <Subtitle>Better <Highlight style={{background: "#6699CC"}}>user experience</Highlight></Subtitle>
        </Slide>
        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>No more passwords!</Highlight></Subtitle>
        </Slide>
        
        
        <Slide>
          <Subtitle>Some <Highlight style={{background: "#6699CC"}}>issues</Highlight> still to be solved</Subtitle>
        </Slide>
        <Slide>
          <Subtitle>User <Highlight style={{background: "#6699CC"}}>credential management</Highlight></Subtitle>
        </Slide>
        <Slide>
          <Image
            src={ChromeManageCreds}
            alt="Chrome can manage some data"
            style={{ objectFit: "contain" }}
          />
        </Slide>
        <Slide>
          <Image
            src={YubicoManager}
            alt="Yubico manager"
            style={{ objectFit: "contain" }}
          />
        </Slide>
        <Slide>
          <Subtitle><Highlight style={{background: "#6699CC"}}>Cross device</Highlight> credentials</Subtitle>
        </Slide>
        <Slide>
          <Subtitle>Lost/stolen authenticator <Highlight style={{background: "#6699CC"}}>device recovery</Highlight></Subtitle>
        </Slide>

        <Slide>
          <Subtitle>
            Webauthn <Highlight style={{background: "#6699CC"}}>might</Highlight> replace Passwords
          </Subtitle>
        </Slide>
        <Slide>
          <Subtitle>
            Webauthn does <Highlight style={{background: "#6699CC"}}>not</Highlight> replace
          </Subtitle>
          <List>
            <li>
              Token based authentication / authorization (OAuth, OIDC, ...)
            </li>
            <li>Identity providers (Auth0)</li>
            <li>...</li>
          </List>
        </Slide>

        <Slide>
          <Subtitle>It's a <Highlight style={{background: "#6699CC"}}>W3C Recommendation</Highlight>!</Subtitle>
        </Slide>
        <Slide>
          <List>
            <li>Chrome</li>
            <li>Firefox</li>
            <li>Edge</li>
            <li>Safari</li>
          </List>
        </Slide>
        <Slide>
          <Subtitle>So where can I <Highlight style={{background: "#6699CC"}}>use this</Highlight> already?</Subtitle>
        </Slide>
        <Slide>
          <List>
            <li>Auth0</li>
            <li>Google</li>
            <li>Github</li>
            <li>...</li>
          </List>
        </Slide>
        <Slide>
            <Image src={Auth0Webauthn1} alt="Auth0 webuathn" />
        </Slide>
        <Slide>
            <Image src={Auth0Webauthn2} alt="Auth0 webuathn" />
        </Slide>
        <Slide>
            <Image src={Auth0Webauthn3} alt="Auth0 webuathn" />
        </Slide>
        <Slide>
          <Browser url="https://webauthn.me" />
        </Slide>

        {/* <Slide>
          <Subtitle>Let's summarize</Subtitle>
          <List>
            <li>Boo passwords!</li>
            <li>One time passwords are cool!</li>
            <li>Webauthn is even cooler!!</li>
          </List>
        </Slide> */}
        <Slide>
          <Subtitle>Let's summarize</Subtitle>
          <List>
            <li>WebAuth-awesome!</li>
          </List>
        </Slide>
        <Slide>
          <Subtitle>
            <a href="https://webauthn.me" target="_blank" style={{ color: "#000", borderColor: "#6699CC" }}>
              webauthn.me
            </a>
          </Subtitle>
        </Slide>
        <Slide>
          <Subtitle>
            <a href="https://www.w3.org/TR/webauthn" target="_blank" style={{ color: "#000", borderColor: "#6699CC"}}>
              w3.org/TR/webauthn
            </a>
          </Subtitle>
        </Slide>
        <Slide>
          <Subtitle>
            <a href="https://auth0.com/blog" target="_blank" style={{ color: "#000", borderColor: "#6699CC" }}>
              auth0.com/blog
            </a>
          </Subtitle>
        </Slide>
        <Slide>
         <Subtitle>
            <a
              style={{ color: "#000", borderColor: "#6699CC" }}
              href="webauthn.sambego.tech"
            >
              webauthn.sambego.tech
            </a>
          </Subtitle>
        </Slide>

        <Slide style={{ background: "#6699CC"}}>
          <Subtitle style={{color: '#fff'}}>Thanks!</Subtitle>
        </Slide>
        <Slide>
          <Image
            src={Poes}
            alt="I've got cat stickers, tweet me @sambego"
            full
            color="#6699CC"
          />
        </Slide>
      </Deck>
    );
  }
}

export default App;
