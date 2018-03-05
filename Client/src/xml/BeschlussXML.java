package xml;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * Ein eingelesender Zeugnisbeschluss.
 * Dieser verweist auf sämtliche Klassen in diesem Package, die alle nur ein XML-Dokument als Objekte darstellen.
 */
@XmlRootElement(name = "Beschluss")
public class BeschlussXML {
    public ZeugnisXML zeugnis;
    public MetadatenXML meta;

}
