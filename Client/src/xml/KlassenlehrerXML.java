package xml;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "Klassenlehrer")
public class KlassenlehrerXML {
    public String publicKey;
    public String privateKey;
}
