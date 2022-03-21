package io.github.intoto.legacy.models;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.github.intoto.legacy.keys.Key;
import io.github.intoto.legacy.keys.Signature;
import io.github.intoto.legacy.lib.NumericJSONSerializer;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 * A metablock class that contains two elements
 *
 * <p>- A signed field, with the signable portion of a piece of metadata. - A signatures field, a
 * list of the signatures on this metadata.
 */
@Deprecated
abstract class Metablock<S extends Signable> {
  S signed;
  ArrayList<Signature> signatures;

  /**
   * Base constructor.
   *
   * <p>Ensures that, at the least, there is an empty list of signatures.
   */
  public Metablock(S signed, ArrayList<Signature> signatures) {
    this.signed = signed;

    if (signatures == null) signatures = new ArrayList<Signature>();
    this.signatures = signatures;
  }

  /**
   * Serialize the current metadata into a JSON file
   *
   * @param filename The filename to which the metadata will be dumped.
   */
  public void dump(String filename) {
    FileWriter writer = null;

    try {
      writer = new FileWriter(filename);
      dump(writer);
      writer.close();
    } catch (IOException e) {
      throw new RuntimeException("Couldn't serialize object: " + e.toString());
    }
  }

  /**
   * Serialize the current metadata into a writer
   *
   * @param writer the target writer
   * @throws java.io.IOException if unable to write to the passed writer.
   */
  public void dump(Writer writer) throws IOException {

    writer.write(dumpString());
    writer.flush();
  }

  /**
   * Serialize the current metadata to a string
   *
   * @return a JSON string representation of the metadata instance
   */
  public String dumpString() {
    Gson gson =
        new GsonBuilder()
            .serializeNulls()
            // Use custom serializer to enforce non-floating point numbers
            .registerTypeAdapter(Double.class, new NumericJSONSerializer())
            .setPrettyPrinting()
            .create();
    return gson.toJson(this);
  }

  /**
   * Signs the current signed payload using the key provided
   *
   * @param privateKey the key used to sign the payload.
   */
  public void sign(Key privateKey) {

    String sig;
    String keyid;
    byte[] payload;
    AsymmetricKeyParameter keyParameters;

    try {
      keyParameters = privateKey.getPrivate();
      if (keyParameters == null || keyParameters.isPrivate() == false) {
        System.out.println("Can't sign with a public key!");
        return;
      }
    } catch (IOException e) {
      System.out.println("Can't sign with this key!");
      return;
    }

    keyid = privateKey.computeKeyId();
    payload = this.signed.JSONEncodeCanonical().getBytes();

    Signer signer = privateKey.getSigner();
    signer.init(true, keyParameters);
    signer.update(payload, 0, payload.length);
    try {
      sig = Hex.toHexString(signer.generateSignature());
    } catch (CryptoException e) {
      System.out.println("Couldn't sign payload!");
      return;
    }

    this.signatures.add(new Signature(keyid, sig));
  }

  /**
   * Public shortcut to call JSONEncodeCanonical on the signed field of this metablock.
   *
   * @param serializeNulls if nulls should be included or not when encoding
   * @return a JSON string representation of this obj
   */
  public String getCanonicalJSON(boolean serializeNulls) {
    return this.signed.JSONEncodeCanonical(serializeNulls);
  }

  public S getSigned() {
    return this.signed;
  }

  public ArrayList<Signature> getSignatures() {
    return this.signatures;
  }
}
