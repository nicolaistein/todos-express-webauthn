window.addEventListener('load', function() {
  
  document.querySelector('form').addEventListener('submit', function(event) {
    if (!window.PublicKeyCredential) { return; }
    
    event.preventDefault();

    console.log("Event in frontend ", event.target);
    
    return fetch('/signup/public-key/challenge', {
      method: 'POST',
      headers: {
        'Accept': 'application/json'
      },
      body: new FormData(event.target),
    })
    .then(function(response) {
      console.log("Reponse in frontend ", response)
      return response.json();
    })
    .then(function(json) {
      // https://chromium.googlesource.com/chromium/src/+/master/content/browser/webauth/uv_preferred.md
      // https://chromium.googlesource.com/chromium/src/+/main/content/browser/webauth/pub_key_cred_params.md

      console.log("json in frontend ");
      console.log(json);


      return navigator.credentials.create({
        publicKey: {
          rp: json.rp,
          user: {
            id: base64url.decode(json.user.id),
            name: json.user.name,
            displayName: json.user.displayName
          },
          challenge: base64url.decode(json.challenge),
          pubKeyCredParams: json.pubKeyCredParams,
          attestation: json.attestation,
          authenticatorSelection: json.authenticatorSelection,
          //extensions: {
          //  credProps: true
          //}
        }
      });


  //    return create(json);
  //    return navigator.credentials.create(params);
    })
    .then(function(credential) {
      console.log("Credential in frontend ", credential);

      return fetch('/login/public-key', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          credential: {
            id: credential.id,
            rawId: base64url.encode(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: base64url.encode(credential.response.clientDataJSON),
              attestationObject: base64url.encode(credential.response.attestationObject)
            }
          },
          method: "webauthn.create"
        })
      });
    })
    .then(function(response) {
      return response.json();
    })
    .then(function(json) {
      window.location.href = json.location;
    })
    .catch(function(error) {
      console.log("Error in frontend ", error.message)
      console.log(error);
    });
  });
  
});
