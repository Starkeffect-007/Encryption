package com.security.encryption.Test_EncryptDecrypt;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class RequestBody {
    @XmlElement String Pass;
    @XmlElement String Text;
    @XmlElement Integer Mode;
    @XmlElement Integer Alg;
}