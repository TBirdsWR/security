package ppc.security_api.cert.entity;

import java.security.PrivateKey;
import java.security.cert.Certificate;

public class CertBean {
    private Certificate[] certificate;
    private PrivateKey privateKey;

    public Certificate[] getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate[] certificate) {
        this.certificate = certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public CertBean(Certificate[] certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public CertBean() {
    }
}
