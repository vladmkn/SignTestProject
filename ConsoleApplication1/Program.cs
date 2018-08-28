using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using CryptoPro.Sharpei;
using CryptoPro.Sharpei.Xml;

public class StoreKey

{
    public static void Main()
    {
        try
        {
            // Create a new XML document.
            XmlDocument xmlDoc = new XmlDocument();

            // Load an XML file into the XmlDocument object.
            xmlDoc.PreserveWhitespace = true;

            bool подписываем = false;

            if (подписываем)
            {
                // Create a new CspParameters object to specify
                // a key container.
                CspParameters cspParams = new CspParameters(1, "Aktiv ruToken CSP v1.0");
                cspParams.KeyContainerName = "NNIIRT";

                // Create a new RSA signing key and save it in the container. 
                RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(cspParams);

                xmlDoc.Load("test.xml");

                // Sign the XML document. 
                ПодписываемXML(xmlDoc, rsaKey);

                Console.WriteLine("XML file signed.");

                // Save the document.
                xmlDoc.Save("test1.xml");
            }
            else
            {
                xmlDoc.Load("test1.xml");

                // Verify the signature of the signed XML.
                Console.WriteLine("Verifying signature...");
                bool result = ПроверяемПодписьXml(xmlDoc);

                // Display the results of the signature verification to 
                // the console.
                if (result)
                {
                    Console.WriteLine("The XML signature is valid.");
                }
                else
                {
                    Console.WriteLine("The XML signature is not valid.");
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }

        Console.ReadKey();

    }

    public static void ПодписываемXML(XmlDocument xmlDoc, RSA key)
    {
        // Check arguments.
        if (xmlDoc == null)
            throw new ArgumentException("xmlDoc");
        if (key == null)
            throw new ArgumentException("key");

        // Create a SignedXml object.
        SignedXml signedXml = new SignedXml(xmlDoc);

        // Add the key to the SignedXml document.
        signedXml.SigningKey = key;

        // Create a reference to be signed.
        Reference reference = new Reference();
        reference.Uri = "";

        // Add an enveloped transformation to the reference.
        XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
        reference.AddTransform(env);

        // Add the reference to the SignedXml object.
        signedXml.AddReference(reference);

        // Compute the signature.
        signedXml.ComputeSignature();

        // Get the XML representation of the signature and save
        // it to an XmlElement object.
        XmlElement xmlDigitalSignature = signedXml.GetXml();

        XmlDocument docPublicKey = new XmlDocument();
        XmlNode xmlPublicKey = docPublicKey.CreateElement("PublicKey"); // даём имя
        xmlPublicKey.InnerXml = key.ToXmlString(false); // и значение
        docPublicKey.AppendChild(xmlPublicKey);
        docPublicKey.Save("pk.xml");

        //RSA keyTest = new RSACryptoServiceProvider();
        //keyTest.FromXmlString(key.ToXmlString(false));

        // Append the element to the XML document.
        xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
    }

    public static Boolean ПроверяемПодписьXml(XmlDocument Doc)
    {
        // Check arguments.
        if (Doc == null)
            throw new ArgumentException("Doc");

        // Create a new SignedXml object and pass it
        // the XML document class.
        SignedXml signedXml = new SignedXml(Doc);

        // Find the "Signature" node and create a new
        // XmlNodeList object.
        XmlNodeList nodeList = Doc.GetElementsByTagName("Signature");

        XmlDocument docPublicKey = new XmlDocument();
        docPublicKey.Load("pk.xml");

        XmlNodeList pkList = docPublicKey.GetElementsByTagName("PublicKey");

        // Throw an exception if no signature was found.
        if (nodeList.Count <= 0)
        {
            throw new CryptographicException("Verification failed: No Signature was found in the document.");
        }

        // Throw an exception if no public key was found.
        if (pkList.Count <= 0)
        {
            throw new CryptographicException("Verification failed: No Public key was found in the document.");
        }

        // This example only supports one signature for
        // the entire XML document.  Throw an exception 
        // if more than one signature was found.
        if (nodeList.Count >= 2)
        {
            throw new CryptographicException("Verification failed: More that one signature was found for the document.");
        }

        // This example only supports one public key for
        // the entire XML document.  Throw an exception 
        // if more than one public key was found.
        if (pkList.Count >= 2)
        {
            throw new CryptographicException("Verification failed: More that one public key was found for the document.");
        }

        RSA key = new RSACryptoServiceProvider();
        key.FromXmlString(pkList[0].InnerXml);

        // Load the first <signature> node.  
        signedXml.LoadXml((XmlElement)nodeList[0]);

        // Check the signature and return the result.
        return signedXml.CheckSignature(key);
    }

    public static void CreateContainerX509()
    {
        CspParameters csp = new CspParameters(1, "Aktiv ruToken CSP v1.0");
        //CspParameters csp = new CspParameters();
        csp.KeyContainerName = "NNIIRT";
        //csp.Flags = CspProviderFlags.UseDefaultKeyContainer;
        //csp.KeyContainerName = "TESTNN5";
        //csp.Flags = CspProviderFlags.UseArchivableKey;

        
        // Initialize an RSACryptoServiceProvider object using
        // the CspParameters object.
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp);
        rsa.PersistKeyInCsp = true;

        //rsa.Clear();

        //// Create some data to sign.
        byte[] data = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 };

        Console.WriteLine("Data			: " + BitConverter.ToString(data));

        //// Sign the data using the Smart Card CryptoGraphic Provider.
        byte[] sig = rsa.SignData(data, "SHA1");

        Console.WriteLine("Signature	: " + BitConverter.ToString(sig));

        //// Verify the data using the Smart Card CryptoGraphic Provider.
        bool verified = rsa.VerifyData(data, "SHA1", sig);

        Console.WriteLine("Verified		: " + verified);
    }

    /// <summary>
    /// Подписывание xml-файла
    /// </summary>
    /// <param name="path">Путь к подписываемому файлу</param>
    public static void SignXml(string path)
    {
        CspParameters cspParameters = new CspParameters(75, null, "NNIIRTTEST111"); ///Идентификатор ключа. Смотрится в "Панель управления Рутокен"

        Gost3410CryptoServiceProvider prov = new Gost3410CryptoServiceProvider(cspParameters);

        X509Certificate2 certificate = prov.ContainerCertificate;
        AsymmetricAlgorithm Key = certificate.PrivateKey;

        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.PreserveWhitespace = true;
        xmlDoc.Load(path);

        SignedXml signedXml = new SignedXml(xmlDoc);
        signedXml.SigningKey = Key;

        Reference reference = new Reference();
        reference.Uri = "";
        reference.DigestMethod = CPSignedXml.XmlDsigGost3411Url;

        XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
        reference.AddTransform(env);

        XmlDsigC14NTransform c14 = new XmlDsigC14NTransform();
        reference.AddTransform(c14);

        signedXml.AddReference(reference);

        KeyInfo keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();

        XmlElement xmlDigitalSignature = signedXml.GetXml();
        xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));

        if (xmlDoc.FirstChild is XmlDeclaration)
            xmlDoc.RemoveChild(xmlDoc.FirstChild);

        xmlDoc.Save(@"d:\temp\test1.xml");
    }

    public static void VerifyXML(string path)
    {
        // Создаем новый XML документ в памяти.
        XmlDocument xmlDocument = new XmlDocument();

        // Сохраняем все пробельные символы, они важны при проверке 
        // подписи.
        xmlDocument.PreserveWhitespace = true;

        // Загружаем подписанный документ из файла.
        xmlDocument.Load(path);

        // Ищем все node "Signature" и сохраняем их в объекте XmlNodeList
        XmlNodeList nodeList = xmlDocument.GetElementsByTagName(
            "Signature", SignedXml.XmlDsigNamespaceUrl);

        Console.WriteLine("Найдено:{0} подпис(ей).", nodeList.Count);

        // Проверяем все подписи.
        for (int curSignature = 0; curSignature < nodeList.Count; curSignature++)
        {
            // Создаем объект SignedXml для проверки подписи документа.
            SignedXml signedXml = new SignedXml(xmlDocument);

            // начиная с .NET 4.5.1 для проверки подписи, необходимо добавить СМЭВ transform в довернные:
#if NETFX451
                signedXml.SafeCanonicalizationMethods.Add("urn://smev-gov-ru/xmldsig/transform");
#endif
            // Загружаем узел с подписью.
            signedXml.LoadXml((XmlElement)nodeList[curSignature]);

            // Проверяем подпись и выводим результат.
            bool result = signedXml.CheckSignature();

            foreach (var keyInfo in signedXml.Signature.KeyInfo)
            {
                foreach (var cert in (keyInfo as KeyInfoX509Data).Certificates)
                {
                    Console.WriteLine(cert.ToString());
                }
            }
            

            // Выводим результат проверки подписи в консоль.
            if (result)
                Console.WriteLine("XML подпись[{0}] верна.", curSignature + 1);
            else
                Console.WriteLine("XML подпись[{0}] не верна.", curSignature + 1);
        }
    }

    public static void GenKey_SaveInContainer(string ContainerName)
    {
        // Create the CspParameters object and set the key container   
        // name used to store the RSA key pair.  
        CspParameters cp = new CspParameters(75, null, ContainerName);
        //cp.KeyContainerName = ContainerName;
        //cp.Flags = CspProviderFlags.UseExistingKey;

        // Create a new instance of RSACryptoServiceProvider that accesses  
        // the key container MyKeyContainerName.  
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cp);

        // Display the key information to the console.  
        Console.WriteLine("Key added to container: \n  {0}", rsa.ToXmlString(true));
    }

    public static void GetKeyFromContainer(string ContainerName)
    {
        // Create the CspParameters object and set the key container   
        // name used to store the RSA key pair.  
        CspParameters cp = new CspParameters();
        cp.KeyContainerName = ContainerName;

        // Create a new instance of RSACryptoServiceProvider that accesses  
        // the key container MyKeyContainerName.  
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cp);

        // Display the key information to the console.  
        Console.WriteLine("Key retrieved from container : \n {0}", rsa.ToXmlString(true));
    }

    public static void DeleteKeyFromContainer(string ContainerName)
    {
        // Create the CspParameters object and set the key container   
        // name used to store the RSA key pair.  
        CspParameters cp = new CspParameters();
        cp.KeyContainerName = ContainerName;

        // Create a new instance of RSACryptoServiceProvider that accesses  
        // the key container.  
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cp);

        // Delete the key entry in the container.  
        rsa.PersistKeyInCsp = false;

        // Call Clear to release resources and delete the key from the container.  
        rsa.Clear();

        Console.WriteLine("Key deleted.");
    }
}