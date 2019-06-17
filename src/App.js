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
  Highlight
} from "@sambego/diorama";

import AnnoyingForm from "./Components/Annoying";
import Webauthn from "./Components/Webauthn";

import Sam from "./img/sam.png";
import Poes from "./img/poes.jpg";
import Pattern from "./img/pattern.png";
import Pattern2 from "./img/pattern-2.png";
import IOSOtp from "./img/iOS-otp.png";
import Magic from "./img/magic-link.png";
import GoogleAuthenticator from "./img/google-authenticator.png";
import Social from "./img/social.png";
import USBAUthenticator from "./img/usb.jpg";
import FastForward from "./img/fast-forward.svg";
import BreachedPW from "./img/breached-pw.png";
import Checkup from "./img/checkup.png";
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

import fireworks from "./video/fireworks.mp4";

class App extends Component {
  render() {
    const code1 =
      "async function() {\n  try {\n      const credentials = \n        await navigator.credentials.create(config);\n    } catch (error) {\n      ...\n    }\n}";
    const code2 =
      "{\n  ...\n  // random, cryptographically secure, at least 16 bytes\n  challenge: createRandomUint8Array().buffer,\n  ...\n }";
    const code3 =
      "{\n  ...\n  // relying party\n  rp: {\n    name: 'Auth0'\n  },\n  ...\n }";
    const code4 =
      "{\n  ...\n  // user information\n  user: {\n    id: createRandomUint8Array(),\n    name: 'Sam Bellen',\n    displayName: 'Sambego'\n  },\n  ...\n }";
    const code5 =
      "{\n  ...\n  // information about the allowed authenticator device\n  authenticatorSelection: {  \n    // optional, can also be 'cross-platform'\n    authenticatorAttachment: 'platform',\n    // optional, can also be 'require ' and 'discouraged'\n    userVerification: 'preferred'\n  },\n  ...\n }";
    const code6 =
      "{\n  ...\n  // information about the attestation, to prove the user's identity\n  // can also be 'indirect' and 'none' to remove identifying information\n  attestation: 'direct',\n  ...\n }";
    const code7 =
      "async function() {\n  try {\n    const credentials = \n      await navigator.credentials.create(createConfig);\n\n    const attestation = \n      await navigator.credentials.get(getConfig);\n  } catch (error) {\n    ...\n  }\n}";
    const code8 = "const getConfig = {\n  publicKey: {\n    ...\n  }\n}";
    const code9 =
      "{\n  ...\n  // random, cryptographically secure, at least 16 bytes\n  challenge: createRandomUint8Array().buffer,\n  ...\n}";
    const code10 =
      "{\n  ...\n  // The allowed credentials\n  allowCredentials: [\n    {\n      id: credentials.rawId,\n      type: 'public-key'\n    }\n  ],\n  ...\n}";
    const code11 =
      "{\n  ...\n  // information about the allowed authenticator device\n  authenticatorSelection: { \n    // optional, can also be 'required' and 'discouraged'\n    userVerification: 'preferred' \n  }\n  ...\n}";
    const challenge =
      "Uint8Array(32) [\n  244  26   255  176  8    247  14   221  \n  177  109  132  138  87   167  124  13   \n  188  168  98   140  240  126  188  214\n  58   101  86   158  217  193  132  253 \n]";

    return (
      <Deck navigation>
        <Slide style={{ background: "#99c794", color: "#fff" }}>
          <Video src={fireworks} loop autoplay full color="#99c794" />
          <Title style={{ color: "#ffffff", position: "relative", zIndex: 1 }}>
            Web authentication API
          </Title>
        </Slide>
        <Slide>
          <Columns>
            <div>
              <Image src={Sam} alt="A picture of me" full color="#99c794" />
            </div>
            <div>
              <Subtitle>Sam Bellen</Subtitle>
              <List>
                <li>Developer Evangelist</li>
                <li>Auth0</li>
                <li>Google Developer Expert</li>
                <li>Fronteers</li>
                <li>I&S London</li>
                <li>@sambego</li>
              </List>
            </div>
          </Columns>
        </Slide>
        <Slide>
          <List>
            <Subtitle>Summary</Subtitle>
            <li>What is webauthn</li>
            <li>How does it work?</li>
            <li>Lets see some code</li>
          </List>
        </Slide>

        <Slide style={{ background: "#99c794", color: "#fff" }}>
          <Title>What is webauthn</Title>
        </Slide>
        <Slide>
          <Subtitle>
            <Highlight>Key based</Highlight> authentication
          </Subtitle>
        </Slide>
        <Slide>
          <Subtitle>
            A <Highlight>private key</Highlight> is used to{" "}
            <Highlight>sign</Highlight> challenges
          </Subtitle>
        </Slide>
        <Slide>
          <Subtitle>
            A <Highlight>public key</Highlight> is used to{" "}
            <Highlight>verify</Highlight> signatures
          </Subtitle>
        </Slide>

        <Slide>
          <Subtitle>
            <Highlight>Why?</Highlight>
          </Subtitle>
        </Slide>
        <Slide>
          <AnnoyingForm />
        </Slide>
        <Slide>
          <Subtitle>
            Passwords are{" "}
            <Highlight style={{ backgroundColor: "#ec5f67" }}>
              annoying
            </Highlight>!
          </Subtitle>
        </Slide>
        <Slide>
          <Subtitle>
            Passwords are often the{" "}
            <Highlight style={{ backgroundColor: "#ec5f67" }}>
              weakest link
            </Highlight>
          </Subtitle>
        </Slide>

        <Slide>
          <Subtitle>
            web authentication could be a <Highlight>better solution</Highlight>!
          </Subtitle>
        </Slide>
        <Slide>
          <Subtitle>
            <Highlight>Hardware authenticator</Highlight>
          </Subtitle>
        </Slide>
        <Slide>
          <Image src={USBAUthenticator} alt="USB Authenticator" />
        </Slide>
        <Slide>
          <List>
            <li>USB</li>
            <li>BLE</li>
            <li>NFC</li>
          </List>
        </Slide>
        <Slide>
          <Subtitle>Who has one?</Subtitle>
        </Slide>
        <Slide>
          <Webauthn />
        </Slide>
        <Slide>
          <Subtitle>
            Most modern devices have a{" "}
            <Highlight>built in authenticator device</Highlight>
          </Subtitle>
        </Slide>
        <Slide>
          <Webauthn platform />
        </Slide>
        <Slide>
          <Subtitle style={{ fontSize: "20rem" }}>🎉</Subtitle>
        </Slide>

        <Slide>
          <Subtitle>
            The created credentials are <Highlight>scoped</Highlight> to the{" "}
            <Highlight>origin that initiated the creation</Highlight>
          </Subtitle>
        </Slide>
        <Slide>
          <Subtitle>
            Allowed authenticators can be{" "}
            <Highlight>filtered and fine-tuned</Highlight>
          </Subtitle>
        </Slide>
        <Slide>
          <List>
            <li>with a trusted certificate</li>
            <li>with user verification</li>
            <li>only internal or external devices</li>
          </List>
        </Slide>

        <Slide style={{ background: "#99c794", color: "#fff" }}>
          <Title>How does it work</Title>
        </Slide>
        <Slide>
          <Subtitle>
            We first need to <Highlight>create new credentials</Highlight>
          </Subtitle>
        </Slide>
        <Slide>
          <Image src={Webauthn1} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Image src={Webauthn2} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Code code={challenge} />
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
          <Subtitle>
            Once registered, we can <Highlight>authenticate</Highlight>
          </Subtitle>
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
          <Image src={Webauthn5} alt="Webauthn schema" />
        </Slide>
        <Slide>
          <Image src={Webauthn6} alt="Webauthn schema" />
        </Slide>

        <Slide style={{ background: "#99c794", color: "#fff" }}>
          <Title>Lets see some code</Title>
        </Slide>
        <Slide>
          <Subtitle>
            <Highlight>Create</Highlight> new credentials
          </Subtitle>
        </Slide>
        <Slide>
          <Code code={code1} />
        </Slide>
        <Slide>
          <Code code={code2} />
        </Slide>
        <Slide>
          <Code code={code3} />
        </Slide>
        <Slide>
          <Code code={code4} />
        </Slide>
        <Slide>
          <Code code={code5} />
        </Slide>
        <Slide>
          <Code code={code6} />
        </Slide>

        <Slide>
          <Subtitle>
            <Highlight>Use the created credentials</Highlight>
          </Subtitle>
        </Slide>
        <Slide>
          <Code code={code7} />
        </Slide>
        <Slide>
          <Code code={code8} />
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
          <Subtitle>
            Some <Highlight>issues</Highlight> still to be solved
          </Subtitle>
        </Slide>
        <Slide>
          <Subtitle>User credential management</Subtitle>
          <List>
            <li>Multiple accounts on one device</li>
            <li>Remove credentials</li>
          </List>
        </Slide>
        <Slide>
          <Subtitle>Cross devices credentials</Subtitle>
        </Slide>
        <Slide>
          <Subtitle>Lost / stolen authenticator device recovery</Subtitle>
        </Slide>

        <Slide>
          <Subtitle>
            It's a <Highlight>W3C Recommendation</Highlight>!
          </Subtitle>
        </Slide>
        <Slide>
          <List>
            <li>Chrome 67</li>
            <li>Firefox 60</li>
            <li>Edge 17723</li>
            <li>Safari Tech Preview (behind a flag)</li>
          </List>
        </Slide>

        <Slide>
          <Subtitle>So where can I use this already?</Subtitle>
        </Slide>
        <Slide>
          <List>
            <li>Google</li>
            <li>Github</li>
            <li>...</li>
          </List>
        </Slide>

        <Slide>
          <Browser url="https://webauthn.me" />
        </Slide>

        <Slide>
          <Subtitle>Let's summarize</Subtitle>
          <List>
            <li>Boo passwords!</li>
            <li>It's key based</li>
            <li>First we create credentials</li>
            <li>Then we use these to authenticate</li>
          </List>
        </Slide>
        <Slide>
          <List>
            <li>
              <a href="https://webauthn.me" target="_blank">
                https://webauthn.me
              </a>
            </li>
            <li>
              <a href="https://auth0.com/blog" target="_blank">
                https://auth0.com/blog
              </a>
            </li>
            <li>
              <a href="https://www.w3.org/TR/webauthn" target="_blank">
                https://www.w3.org/TR/webauthn
              </a>
            </li>
          </List>
        </Slide>
        <Slide>
          <Subtitle>https://webauthn.sambego.tech</Subtitle>
        </Slide>
        <Slide>
          <Subtitle>Thanks!</Subtitle>
        </Slide>
        <Slide>
          <Image
            src={Poes}
            alt="I've got cat stickers, tweet me @sambego"
            full
            color="#99c794"
          />
        </Slide>
      </Deck>
    );
  }
}

export default App;
