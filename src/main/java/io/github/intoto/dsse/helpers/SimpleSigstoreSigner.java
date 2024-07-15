package io.github.intoto.dsse.helpers;

import dev.sigstore.KeylessSigner;
import dev.sigstore.KeylessSignerException;
import dev.sigstore.bundle.Bundle;
import io.github.intoto.dsse.models.Signer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

public class SimpleSigstoreSigner implements Signer {
    private String keyId;
    Optional<Bundle.DSSESignature> dsseSignature;
    Bundle result;

    public byte[] sign(byte[] payload) throws InvalidAlgorithmParameterException, CertificateException,  IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, KeylessSignerException {
        KeylessSigner functionary = new KeylessSigner.Builder().sigstorePublicDefaults().build();
        this.result = functionary.sign(payload);

        // set keyId
        X509Certificate certificate = (X509Certificate) (this.result.getCertPath().getCertificates().getFirst());
        String oid = "1.3.6.1.4.1.57264.1.8";
        byte[] extensionValue = certificate.getExtensionValue(oid);
        String issuer = new String(extensionValue, StandardCharsets.UTF_8);
        this.keyId = issuer.substring(4);
        Object subAltArr = certificate.getSubjectAlternativeNames().toArray()[0];
        String subAltName = subAltArr.toString();
        subAltName = subAltName.substring(4, subAltName.length() - 1);
        this.keyId = keyId.concat(" " + subAltName);

        this.dsseSignature = result.getDSSESignature();
        return dsseSignature.get().getSignature();
    }

    @Override
    public String getKeyId() {
        if (this.keyId.isEmpty()) {
            throw new RuntimeException("Sign the artifact to initialize keyId");
        }
        return this.keyId;
    }

    public byte[] getPayload() {
        if (this.dsseSignature.isEmpty()) {
            throw new RuntimeException("Cannot retrieve and unsigned payload");
        }
        return this.dsseSignature.get().getPayload().getBytes(StandardCharsets.UTF_8);
    }

    public Bundle getResult() {
        return this.result;
    }
}
