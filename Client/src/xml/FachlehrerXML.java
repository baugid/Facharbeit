package xml;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "Fachlehrer")
public class FachlehrerXML {
    public String publicKey;
    public String privateKey;
}
