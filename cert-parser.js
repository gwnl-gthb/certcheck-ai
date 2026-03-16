import * as asn1js from 'https://cdn.jsdelivr.net/npm/asn1js@3.0.5/+esm';

// --- DICTIONNAIRES DE TRADUCTION ---

const ASN1_UNIVERSAL_NAMES = {
    0: "Reserved/EndOfContent",
    1: "Boolean",
    2: "Integer",
    3: "BitString",
    4: "OctetString",
    5: "Null",
    6: "ObjectIdentifier",
    7: "ObjectDescriptor",
    8: "External/Instance-of",
    9: "Real",
    10: "Enumerated",
    12: "UTF8String",
    16: "Sequence",
    17: "Set",
    18: "NumericString",
    19: "PrintableString",
    20: "TeletexString",
    21: "VideotexString",
    22: "IA5String",
    23: "UTCTime",
    24: "GeneralizedTime"
};

const OID_MAP = {
    //DN
    "2.5.4.3": "Common Name (CN)",
    "2.5.4.6": "Country (C)",
    "2.5.4.10": "Organization (O)",
    "2.5.4.11": "Organizational Unit (OU)",
    "2.5.4.97": "Organization Identifier",
    "2.5.4.42": "Given Name",
    "2.5.4.4": "Surname",
    "2.5.4.5": "Serial Number (DN)",
    //Extension
    "2.5.29.15": "Key Usage",
    "2.5.29.17": "Subject Alternative Name",
    "2.5.29.19": "Basic Constraints",
    "2.5.29.32": "Certificate Policies",
    "2.5.29.37": "Extended Key Usage",
    "2.5.29.14": "Subject Key Identifier",
    "2.5.29.35": "Authority Key Identifier",
    "2.5.29.31": "CRL Distribution Points",
    "1.3.6.1.5.5.7.1.1": "Authority Information Access",
    "1.3.6.1.5.5.7.1.3": "QC Statements",
    //CAB forum
    "2.23.140.3.1": "CABF Organization Identifier",
    "1.3.6.1.4.1.11129.2.4.2": "SCT List (Certificate Transparency)"
};

const ALGO_MAP = {
    "1.2.840.113549.1.1.1": "RSA Encryption",
    "1.2.840.113549.1.1.11": "SHA-256 with RSA",
    "1.2.840.113549.1.1.12": "SHA-384 with RSA",
    "1.2.840.113549.1.1.13": "SHA-512 with RSA",
    "1.2.840.10045.4.3.2": "ECDSA with SHA-256",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.2.840.113549.1.1.5": "SHA-1 with RSA (OBSOLETE)"
};

const EKU_MAP = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "ocspSigning",
    "1.3.6.1.4.1.311.10.3.4": "documentSigning (MS)",
    "1.2.840.113583.1.1.5":"PdfAuthenticDocumentsTrust"
};

const KEY_USAGE_LABELS = [
    "digitalSignature", "nonRepudiation", "keyEncipherment", 
    "dataEncipherment", "keyAgreement", "keyCertSign", 
    "cRLSign", "encipherOnly", "decipherOnly"
];

const AIA_TYPES = {
    "1.3.6.1.5.5.7.48.1": "OCSP Responder",
    "1.3.6.1.5.5.7.48.2": "CA Issuers (Cert URL)"
};

const QC_STATEMENTS_MAP = {
    "0.4.0.1862.1.1": "QC-Compliance (Qualified Certificate)",
    "0.4.0.1862.1.3": "QC-RetentionPeriod",
    "0.4.0.1862.1.4": "QC-QSCD (Hardware Secure Device)",
    "0.4.0.1862.1.5": "QC-PDS (PKI Disclosure Statement)",
    "0.4.0.1862.1.6": "QC-Type",
    "0.4.0.1862.1.6.1": "QC-Type-Signature",
    "0.4.0.1862.1.6.2": "QC-Type-Seal",
    "0.4.0.1862.1.6.3": "QC-Type-Web",
    "0.4.0.19495.2": "QC-PSD2-Extension",
    "0.4.0.19495.1.1": "PSP_AS (Account Servicing)",
    "0.4.0.19495.1.2": "PSP_PI (Payment Initiation)",
    "0.4.0.19495.1.3": "PSP_AI (Account Information)",
    "0.4.0.19495.1.4": "PSP_IC (Issuing of Card-based Instruments)"
};


const GENERAL_NAME_TAGS = {
    0: "OtherName",
    1: "rfc822Name (Email)",
    2: "dNSName",
    3: "x400Address",
    4: "directoryName",
    5: "ediPartyName",
    6: "uniformResourceIdentifier (URI)",
    7: "iPAddress",
    8: "registeredID"
};

const CABF_MAP = {
    // Baseline Requirements - TLS
    "2.23.140.1.1": "CABF: Extended Validation (EV) TLS",
    "2.23.140.1.2.1": "CABF: Domain Validated (DV) TLS",
    "2.23.140.1.2.2": "CABF: Organization Validated (OV) TLS",
    "2.23.140.1.2.3": "CABF: Individual Validated (IV) TLS",
    
    // Code Signing
    "2.23.140.1.4.1": "CABF: Code Signing (Baseline)",
    "2.23.140.1.3": "CABF: EV Code Signing",

    // S/MIME (Nouveaux OIDs 2023)
    "2.23.140.1.5.1": "CABF: S/MIME Mailbox Validated",
    "2.23.140.1.5.2": "CABF: S/MIME Organization Validated",
    "2.23.140.1.5.3": "CABF: S/MIME Sponsor Validated",
    "2.23.140.1.5.4": "CABF: S/MIME Individual Validated"
};

// --- UTILITAIRES ---
function hexToUtf8(hex) {
    if (!hex) return "";
    try {
        const bytes = new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const decoded = new TextDecoder().decode(bytes);
        
        // Filtre : on n'accepte que les caractères imprimables standards
        // Cela évite d'afficher les tags ASN.1 (0x13, 0x0C, etc.) comme du texte
        const isPrintable = Array.from(decoded).every(char => {
            const code = char.charCodeAt(0);
            return (code >= 32 && code <= 126) || code === 10 || code === 13;
        });

        return isPrintable ? decoded.trim() : "";
    } catch (e) { return ""; }
}

function getRSAModulusSize(hex) {
    const cleanHex = (hex || "").replace(/^00+/, '');
    return cleanHex.length * 4;
}

function decodeSCT(node) {
    let hex = "";
    // 1. Extraction récursive de la valeur hex la plus profonde
    if (node.tagNumber === 4 && node.value && node.value.length > 100) {
        hex = node.value;
    } else if (node.children) {
        // On cherche dans les enfants si le parent est une SEQUENCE ou un wrapper
        const deepNode = node.children.find(c => c.value && c.value.length > 100);
        if (deepNode) hex = deepNode.value;
    }

    if (!hex) return "Données SCT non détectées";

    try {
        let scts = [];
        // 2. Localisation du début de la liste TLS
        // Un SCT v1 commence par 00 (version) suivi de 32 octets de LogID.
        // On cherche le marqueur '00' suivi d'un LogID plausible.
        let offset = hex.indexOf("00");
        
        // Si le premier 00 est un header de longueur (ex: 007e), on saute.
        // On valide par la présence d'un timestamp 8 octets plus loin (+66 chars hex)
        let count = 1;
        while (offset !== -1 && offset + 82 <= hex.length) {
            const timestampHex = hex.substring(offset + 66, offset + 82);
            const timestampMs = Number(BigInt("0x" + timestampHex));

            // Une date SCT doit être comprise entre 2015 et 2035
            if (timestampMs > 1420070400000 && timestampMs < 2051222400000) {
                const logId = hex.substring(offset + 2, offset + 66).toUpperCase();
                const date = new Date(timestampMs).toLocaleString('fr-FR', { 
                    timeZone: 'UTC', year: 'numeric', month: '2-digit', day: '2-digit',
                    hour: '2-digit', minute: '2-digit', second: '2-digit'
                });

                scts.push(`[SCT #${count}] ${getLogName(logId)} | Date: ${date} UTC`);
                count++;
                
                // Saut vers le prochain SCT : Header(94 hex) + Signature (environ 144 hex)
                // Pour être robuste, on cherche le prochain '00' au moins 200 chars plus loin
                offset = hex.indexOf("00", offset + 200);
            } else {
                // Si la date n'est pas valide, ce n'est pas un début de SCT, on cherche le '00' suivant
                offset = hex.indexOf("00", offset + 2);
            }
            
            if (count > 5) break; 
        }

        return scts.length > 0 ? scts.join(" || ") : "Structure binaire SCT complexe (non décodée)";
    } catch (e) {
        return "Erreur binaire : " + e.message;
    }
}

function getLogName(id) {
    const logs = {
        "007E008ECA470BACDE6AF3A206B0A47A84B746FE1FC6BF953E25E69B4EE40248F3": "Google 'Xenon'",
        "7E008ECA470BACDE6AF3A206B0A47A84B746FE1FC6BF953E25E69B4EE40248F3": "Google 'Xenon'",
        "4C63DC98E59C1DAB88F61E8A3DDEAE8FAB44A3377B5F9B94C3FBA19CFCC1BE26": "Cloudflare 'Nimbus'",
        "604C9AAF7A7F775F01D406FC920DC899EB0B1C7DF8C9521BFAFA17773B978BC9": "DigiCert 'Yeti'",
        "EECD19075197EF055A1AEEF20754248870A6D3503C333B3F0B16935B7E111976": "Google 'Pilot'"
    };
    // On nettoie l'ID pour la comparaison
    const cleanId = id.startsWith("00") ? id : id; 
    for (let key in logs) {
        if (cleanId.includes(key)) return logs[key];
    }
    return "Log: " + id.substring(0, 12) + "...";
}

function decodeCABFOrgId(node) {
    let details = {
        scheme: "",
        country: "",
        state: "",
        reference: ""
    };

    // On parcourt les enfants de la SEQUENCE contenue dans l'OCTET STRING
    function walk(n) {
        if (n.value) {
            const val = hexToUtf8(n.value).trim();
            
            // Tag [0] IMPLICIT pour StateOrProvince
            if (n.tagNumber === 0 && n.tagClass === 2) {
                details.state = val;
                n["x509-name"] = "Registration State/Province";
                n["x509-decoded"] = val;
            } 
            // Autres champs selon leur position ou type
            else if (val.length === 3 && !details.scheme) {
                details.scheme = val;
                n["x509-name"] = "Registration Scheme";
                n["x509-decoded"] = val;
            }
            else if (val.length === 2 && !details.country) {
                details.country = val;
                n["x509-name"] = "Registration Country";
                n["x509-decoded"] = val;
            }
            else if (val.length > 3 || (details.scheme && details.country)) {
                details.reference = val;
                n["x509-name"] = "Registration Reference";
                n["x509-decoded"] = val;
            }
        }
        if (n.children) n.children.forEach(walk);
    }

    walk(node);

    let parts = [];
    if (details.scheme) parts.push(`Scheme: ${details.scheme}`);
    if (details.country) parts.push(`Country: ${details.country}`);
    if (details.state) parts.push(`Province: ${details.state}`);
    if (details.reference) parts.push(`Ref: ${details.reference}`);

    return parts.length > 0 ? parts.join(" | ") : "Format CABF OrgId non reconnu";
}

function decodeAIA(node) {
    let aiaInfo = [];

    function walk(n) {
        if (n.tagNumber === 16 && n.children && n.children.length >= 2) {
            let type = null;
            let url = null;

            n.children.forEach(child => {
                // 1. On identifie le type via l'OID
                if (child.tagNumber === 6 && typeof child.oid === 'string') {
                    if (AIA_TYPES[child.oid]) type = AIA_TYPES[child.oid];
                }
                
                // 2. On récupère l'URL (IA5String ou tag contextuel interpreté comme OID)
                // On vérifie la valeur brute si l'OID est un objet ou absent
                if (child.value) {
                    const decoded = hexToUtf8(child.value);
                    if (decoded.startsWith("http")) {
                        url = decoded;
                    }
                }
            });

            if (type && url) {
                aiaInfo.push(`${type}: ${url}`);
            }
        }
        if (n.children) n.children.forEach(walk);
    }

    walk(node);
    return aiaInfo.length > 0 ? aiaInfo.join(" | ") : "Format AIA non reconnu ou vide";
}

function decodeSAN(node) {
    let altNames = [];

    function walk(n) {
        // On ne décode que si ce n'est pas une SEQUENCE (16)
        // et que c'est un tag GeneralName connu (1, 2, 6, 7)
        if (n.tagNumber !== 16 && n.value && GENERAL_NAME_TAGS[n.tagNumber]) {
            const typeLabel = GENERAL_NAME_TAGS[n.tagNumber];
            const decodedValue = hexToUtf8(n.value);

            // On vérifie que c'est une chaîne lisible
            if (decodedValue && (decodedValue.includes(".") || decodedValue.includes("@"))) {
                altNames.push(`${typeLabel}: ${decodedValue}`);
                
                // On répare proprement l'enfant pour le JSON final
                n["x509-name"] = typeLabel;
                n["x509-decoded"] = decodedValue;
            }
        }
        if (n.children) n.children.forEach(walk);
    }

    walk(node);
    return altNames.length > 0 ? altNames.join(" | ") : "Aucun nom alternatif valide";
}

function decodeQCStatements(node) {
    let statements = [];
    let pdsDetails = [];
    let psd2Details = [];

    function findDataInSiblings(siblings) {
        let url = "";
        let lang = "";
        siblings.forEach(s => {
            if (s.children && s.children.length > 0) {
                const res = findDataInSiblings(s.children);
                if (res.url) url = res.url;
                if (res.lang) lang = res.lang;
            } else if (s.value) {
                const val = hexToUtf8(s.value).trim();
                if (val.startsWith("http")) {
                    url = val;
                    s["x509-name"] = "PDS URL";
                    s["x509-decoded"] = val;
                } else if (val.length === 2 && /^[A-Z]{2}$/i.test(val)) {
                    lang = val.toUpperCase();
                    s["x509-name"] = "PDS Language";
                    s["x509-decoded"] = lang;
                }
            }
        });
        return { url, lang };
    }

    // Nouvelle sous-fonction pour PSD2
    function extractPSD2Data(siblings) {
        let roles = [];
        let texts = [];
        
        siblings.forEach(s => {
            if (s.tagNumber === 6 && typeof s.oid === 'string') {
                const roleLabel = QC_STATEMENTS_MAP[s.oid];
                if (roleLabel) roles.push(roleLabel);
            } else if ([12, 19, 22].includes(s.tagNumber)) { // UTF8, PrintString, IA5
                const txt = hexToUtf8(s.value).trim();
                if (txt) {
                    texts.push(txt);
                    s["x509-decoded"] = txt; // Marquer le noeud enfant
                }
            }
            if (s.children) {
                const sub = extractPSD2Data(s.children);
                roles = roles.concat(sub.roles);
                texts = texts.concat(sub.texts);
            }
        });
        return { roles: [...new Set(roles)], texts };
    }

    function walk(n) {
        if (n.tagNumber === 6 && typeof n.oid === 'string') {
            const label = QC_STATEMENTS_MAP[n.oid];
            if (label) statements.push(label);
        }

        if (n.children) {
            // Cas 1 : PDS (URLs et Langues)
            if (n.children.some(c => c.oid === "0.4.0.1862.1.5")) {
                const data = findDataInSiblings(n.children);
                if (data.url) pdsDetails.push(`URL: ${data.url}${data.lang ? " (" + data.lang + ")" : ""}`);
            }
            
            // Cas 2 : PSD2 (Rôles banquaires)
            if (n.children.some(c => c.oid === "0.4.0.19495.2")) {
                const psd2 = extractPSD2Data(n.children);
                if (psd2.roles.length > 0 || psd2.texts.length > 0) {
                    psd2Details.push(`Roles: ${psd2.roles.join(", ")} | Authority: ${psd2.texts.join(" / ")}`);
                }
            }

            n.children.forEach(walk);
        }
    }

    walk(node);

    let result = [];
    if (statements.length > 0) result.push(`Statements: ${statements.join(", ")}`);
    if (pdsDetails.length > 0) result.push(`PDS Info: ${pdsDetails.join(" | ")}`);
    if (psd2Details.length > 0) result.push(`PSD2: ${psd2Details.join(" | ")}`);

    return result.length > 0 ? result.join(" || ") : "Aucun QCStatement reconnu";
}

function decodePolicies(node) {
    let policies = [];
    let cpsUrls = [];

    function walk(n) {
        if (n.tagNumber === 6 && typeof n.oid === 'string') {
            // On cherche dans l'OID_MAP (pour les standards) ou CABF_MAP
            const label = CABF_MAP[n.oid] || n.oid;
            
            if (n.oid !== "1.3.6.1.5.5.7.2.1" && n.oid !== "1.3.6.1.5.5.7.2.2") {
                policies.push(label);
            }
        }
        if (n.value) {
            const decoded = hexToUtf8(n.value);
            if (decoded.startsWith("http")) cpsUrls.push(decoded);
        }
        if (n.children) n.children.forEach(walk);
    }

    walk(node);
    
    let result = [];
    if (policies.length > 0) result.push(`Policies: ${policies.join(", ")}`);
    if (cpsUrls.length > 0) result.push(`CPS: ${cpsUrls.join(" | ")}`);
    
    return result.length > 0 ? result.join(" || ") : "Aucune politique détectée";
}

function decodeCRL(node) {
    let urls = [];

    function walk(n) {
        // 1. On cherche la valeur textuelle
        if (n.value) {
            const decoded = hexToUtf8(n.value);
            
            // 2. Si ça ressemble à une URL, on l'ajoute
            // On accepte le tag universel 22 (IA5String) 
            // OU le tag contextuel 6 (souvent utilisé pour les URIs dans les CRL)
            if (decoded.startsWith("http")) {
                urls.push(decoded);
                
                // On en profite pour nommer proprement le nœud dans l'interface
                n["x509-name"] = "CRL URL";
                n["x509-decoded"] = decoded;
            }
        }
        
        if (n.children) n.children.forEach(walk);
    }

    walk(node);
    
    // Suppression des doublons éventuels
    const uniqueUrls = [...new Set(urls)];
    return uniqueUrls.length > 0 ? uniqueUrls.join(" | ") : "Aucune URL de CRL trouvée";
}

function decodeBasicConstraints(node) {
    let isCA = false;
    let pathLen = null;

    // La structure est une SEQUENCE à l'intérieur de l'OCTET STRING
    function walk(n) {
        // Le booléen cA (tag 1)
        if (n.tagNumber === 1) {
            isCA = (n.value.toLowerCase() === "ff");
        }
        // L'entier pathLen (tag 2)
        else if (n.tagNumber === 2) {
            pathLen = parseInt(n.value, 16);
        }
        if (n.children) n.children.forEach(walk);
    }

    walk(node);
    
    let result = `Subject is a CA: ${isCA ? "YES" : "NO"}`;
    if (isCA && pathLen !== null) {
        result += ` | Path Length Constraint: ${pathLen}`;
    }
    return result;
}

function decodeAKI(node) {
    let keyId = "";

    function walk(n) {
        // Dans ton JSON, l'identifiant est dans un noeud tagNumber: 0
        // On vérifie qu'il y a une valeur et pas d'enfants (noeud terminal)
        if (n.tagNumber === 0 && n.value && (!n.children || n.children.length === 0)) {
            keyId = n.value.match(/.{1,2}/g).join(':').toUpperCase();
        } 
        // Cas alternatif si le parser le voit comme un OCTET STRING
        else if (n.tagNumber === 4 && n.value) {
            keyId = n.value.match(/.{1,2}/g).join(':').toUpperCase();
        }
        
        if (n.children) n.children.forEach(walk);
    }

    walk(node);
    return keyId ? keyId : "Identifiant introuvable";
}

function decodeSKI(node) {
    let keyId = "";

    // Le SKI est un OCTET STRING (tag 4) à l'intérieur de l'OCTET STRING de l'extension
    function walk(n) {
        if (n.tagNumber === 4 && n.value && (!n.children || n.children.length === 0)) {
            keyId = n.value.match(/.{1,2}/g).join(':').toUpperCase();
        }
        if (n.children) n.children.forEach(walk);
    }

    walk(node);
    return keyId || "Identifiant SKI introuvable";
}

function decodeKeyUsage(hex) {
    if (hex.length < 2) return hex;
    const val = parseInt(hex.substring(hex.length - 2), 16);
    let usages = [];
    for (let i = 0; i < 8; i++) {
        if ((val >> (7 - i)) & 1) usages.push(KEY_USAGE_LABELS[i]);
    }
    return usages.join(", ");
}

// --- LOGIQUE PRINCIPALE ---
function mapASN1toCustomJSON(asn1Item) {
    if (!asn1Item || !asn1Item.idBlock) return null;

    const tagNumber = asn1Item.idBlock.tagNumber;
    const tagClass = asn1Item.idBlock.tagClass; // 1: Universal, 2: Application, 3: Context-specific, 4: Private

    // Génération d'un nom lisible
    let typeLongName = "";
    if (tagClass === 1) {
        typeLongName = `Universal ${ASN1_UNIVERSAL_NAMES[tagNumber] || "Unknown"}`;
    } else if (tagClass === 3) {
        typeLongName = `Context-Specific [${tagNumber}]`;
    } else if (tagClass === 2) {
        typeLongName = `Application [${tagNumber}]`;
    } else {
        typeLongName = `Private [${tagNumber}]`;
    }

    let hexValue = "";
    const view = asn1Item.valueBlock?.valueHexView || asn1Item.valueBlock?.valueBeforeDecode;
    if (view) hexValue = Array.from(new Uint8Array(view)).map(b => b.toString(16).padStart(2, '0')).join('');

    const node = {
        tagNumber,
        tagClass,
        typeName: typeLongName, // <--- Nom long et compréhensible
        value: hexValue,
        "x509-name": "ASN1 Element",
        "x509-binary": hexValue,
        "x509-decoded": ""
    };

    if (tagNumber === 6) node.oid = asn1Item.valueBlock.toString();

    if (asn1Item.valueBlock?.value && Array.isArray(asn1Item.valueBlock.value)) {
        node.children = asn1Item.valueBlock.value.map(mapASN1toCustomJSON).filter(c => c);
    }
    return node;
}

function enrichNode(node, path = "root") {
    if (!node) return;

    // 1. Version & Serial
    if (node.tagNumber === 2) {
        // SÉCURITÉ : Une version X.509 (v1, v2, v3) a une valeur hex de 1 ou 2 octets max (00, 01, 02)
        // Si la valeur est plus longue, ce n'est PAS une version, c'est une donnée (DNS, etc.)
        const isShortValue = node.value && node.value.length <= 4;

        if (isShortValue && (path === "root.children[0].children[0]" || path.endsWith(".children[0].children[0]"))) {
            node["x509-name"] = "Version";
            node["x509-decoded"] = `v${parseInt(node.value, 16) + 1}`;
        } 
        else if (path === "root.children[0].children[1]") {
            node["x509-name"] = "Serial Number";
            node["x509-decoded"] = node.value.match(/.{1,2}/g)?.join(':').toUpperCase();
        } 
        else {
            // Cas du dNSName ou autre tag contextuel [2]
            const decoded = hexToUtf8(node.value);
            // Si ça contient un point, c'est un domaine, sinon on affiche l'hex ou l'entier
            if (decoded.includes(".")) {
                node["x509-name"] = "dNSName";
                node["x509-decoded"] = decoded;
            } else {
                // Pour les autres entiers (ex: pathLen dans Basic Constraints)
                node["x509-decoded"] = parseInt(node.value, 16).toString();
            }
        }
    }

    // 2. Dates
    if (node.tagNumber === 23 || node.tagNumber === 24) {
        node["x509-name"] = path.includes("children[0]") ? "Not Before" : "Not After";
        const raw = hexToUtf8(node.value);
        let year = raw.substring(0, 2);
        year = parseInt(year) < 50 ? "20" + year : "19" + year;
        node["x509-decoded"] = `${raw.substring(4, 6)}/${raw.substring(2, 4)}/${year} ${raw.substring(6, 8)}:${raw.substring(8, 10)} UTC`;
    }

    // 3. Enfants (DN, Clé, Extensions)
    if (node.children) {
        let lastOIDLabel = null;
        node.children.forEach((child, i) => {
            // Clé Publique
            if (path === "root.children[0].children[6]" && child.tagNumber === 3) {
                child["x509-name"] = "Subject Public Key";
                const modulus = child.children?.[0]?.children?.[0];
                if (modulus && modulus.tagNumber === 2) {
                    child["x509-decoded"] = `RSA ${getRSAModulusSize(modulus.value)} bits`;
                }
            }

            // OIDs
           if (child.tagNumber === 6) {
                // 1. Détecter si c'est un OID valide ou une URL masquée
                // Si l'OID est un objet [object Object], c'est une URL que asn1js n'a pas pu parser
                const isRealOID = (typeof child.oid === 'string' && child.oid.includes('.'));

                if (isRealOID) {
                    const label = OID_MAP[child.oid] || ALGO_MAP[child.oid] || QC_STATEMENTS_MAP[child.oid] || CABF_MAP[child.oid] || child.oid;
                    child["x509-name"] = "Identifier";
                    child["x509-decoded"] = label;
                    lastOIDLabel = label;
                    
                    // Si c't'une extension, on nomme le bloc parent
                    if (OID_MAP[child.oid]) {
                        node["x509-name"] = label;
                    }
                } else {
                    // 2. C'EST ICI QU'ON DECODE LE NOEUD FINAL
                    // On force le décodage de la valeur binaire en UTF-8
                    const decodedString = hexToUtf8(child.value);
                    
                    // Si ça ressemble à une URL, on la marque proprement
                    if (decodedString.includes("http")) {
                        child["x509-name"] = "URL";
                        child["x509-decoded"] = decodedString;
                    } else {
                        child["x509-decoded"] = decodedString;
                    }
                    
                    // On supprime l'OID corrompu pour nettoyer le JSON
                    delete child.oid; 
                }
            }
            // Criticité
            else if (child.tagNumber === 1 && lastOIDLabel) {
                node["criticality"] = (child.value === "ff") ? "CRITICAL" : "NOT CRITICAL";
                child["x509-name"] = "Criticality";
                child["x509-decoded"] = node["criticality"];
            }
            // Valeurs liées aux OID
            else if (lastOIDLabel) {
                // String simple (DN)
                if ([12, 19, 22].includes(child.tagNumber)) {
                    child["x509-name"] = lastOIDLabel;
                    child["x509-decoded"] = hexToUtf8(child.value);
                }
                // Contenu Extension (OCTET STRING)
                else if (child.tagNumber === 4) {
                    child["x509-name"] = lastOIDLabel + " (Contenu)";
                    
                    if (lastOIDLabel === "Key Usage") {
                        // On cherche le BIT STRING à l'intérieur de l'OCTET STRING
                        const bitStr = child.children?.find(c => c.tagNumber === 3);
                        if (bitStr) child["x509-decoded"] = decodeKeyUsage(bitStr.value);
                    } 
                    else if (lastOIDLabel === "Extended Key Usage") {
                        // On cherche les OID à l'intérieur
                        let usages = [];
                        function findEKU(n) {
                            if (n.tagNumber === 6) usages.push(EKU_MAP[n.oid] || n.oid);
                            if (n.children) n.children.forEach(findEKU);
                        }
                        findEKU(child);
                        child["x509-decoded"] = usages.join(", ");
                    }
                    else if (lastOIDLabel === "Authority Information Access") {
                      child["x509-decoded"] = decodeAIA(child);
                    }
                    else if (lastOIDLabel === "Authority Key Identifier") {
                        child["x509-decoded"] = decodeAKI(child);
                    }
                    else if (lastOIDLabel === "Subject Key Identifier") {
                        child["x509-decoded"] = decodeSKI(child);
                    }
                    else if (lastOIDLabel === "Basic Constraints") {
                        child["x509-decoded"] = decodeBasicConstraints(child);
                    }
                    else if (lastOIDLabel === "CRL Distribution Points") {
                        child["x509-decoded"] = decodeCRL(child);
                    }
                    else if (lastOIDLabel === "Certificate Policies") {
                        child["x509-decoded"] = decodePolicies(child);
                    }
                    else if (lastOIDLabel === "QC Statements") {
                        child["x509-decoded"] = decodeQCStatements(child);
                    }
                    else if (lastOIDLabel === "CABF Organization Identifier") {
                        child["x509-decoded"] = decodeCABFOrgId(child);
                    }
                    else if (lastOIDLabel === "SCT List (Certificate Transparency)") {
                        child["x509-decoded"] = decodeSCT(child);
                    }
                    else if (lastOIDLabel === "Subject Alternative Name") {
                        child["x509-name"] = "Subject Alternative Name (Contenu)"; // On force le nom propre
                        child["x509-decoded"] = decodeSAN(child);
                    }
                    else {
                        child["x509-decoded"] = "Voir détails enfants";
                    }
                }
            }
            enrichNode(child, `${path}.children[${i}]`);
        });
    }
}

window.parseCertificate = async function(pemString) {
    const b64 = pemString.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/[^A-Za-z0-9+/=]/g, "");
    const bytes = new Uint8Array(atob(b64).split("").map(c => c.charCodeAt(0)));
    const asn1 = asn1js.fromBER(bytes.buffer);
    const root = mapASN1toCustomJSON(asn1.result);
    enrichNode(root);
    return [root];
};

function renderNode(node, depth = 0) {
    const hasChildren = node.children && node.children.length > 0;
    const container = document.createElement('div');
    container.className = `mb-1 border-l-2 border-gray-200 pl-2 transition-all`;

    // Couleurs des tags
    const tagColors = {
        6: 'bg-amber-100 text-amber-800',   // OID
        4: 'bg-blue-100 text-blue-800',     // Octet String
        2: 'bg-emerald-100 text-emerald-800', // Integer
        16: 'bg-gray-200 text-gray-700',    // Sequence
        1: 'bg-red-100 text-red-800'        // Boolean
    };
    const tagClass = tagColors[node.tagNumber] || 'bg-gray-100 text-gray-600';

    // Préparation des métadonnées
    const isCritical = node["criticality"] === "CRITICAL";
    const decodedValue = node["x509-decoded"] || "";
    const labelName = node["x509-name"] !== "ASN1 Element" ? node["x509-name"] : node.typeName;
    const binarySize = node.value ? Math.ceil(node.value.length / 2) : 0;

    // Construction du contenu de l'élément
    const headerHtml = `
        <div class="flex flex-col gap-1 py-1 cursor-pointer">
            <div class="flex items-center flex-wrap gap-2 text-[10px]">
                ${hasChildren ? '<i data-lucide="chevron-right" class="w-3 h-3 text-gray-400"></i>' : '<span class="w-3"></span>'}
                <span class="font-bold text-gray-700 uppercase tracking-tight">${labelName}</span>
                <span class="${tagClass} px-1 rounded font-mono">${node.typeName}</span>
                <span class="text-gray-400 font-mono italic">${binarySize}B</span>
                ${isCritical ? '<span class="bg-red-500 text-white px-1 rounded font-bold animate-pulse">CRITICAL</span>' : ''}
            </div>
            ${decodedValue ? `<div class="bg-blue-50 border border-blue-100 rounded px-2 py-1 text-sm text-blue-900 font-medium shadow-sm ml-4">${decodedValue}</div>` : ''}
        </div>
    `;

    if (hasChildren) {
        // Si il y a des enfants, on utilise DETAILS / SUMMARY
        const details = document.createElement('details');
        details.className = "group";
        // On laisse ouvert par défaut seulement pour les premiers niveaux
        if (depth < 2) details.open = true;

        const summary = document.createElement('summary');
        summary.className = "list-none outline-none";
        summary.innerHTML = headerHtml;

        const childrenContainer = document.createElement('div');
        childrenContainer.className = "ml-4 border-l border-gray-100";

        node.children.forEach(child => {
            childrenContainer.appendChild(renderNode(child, depth + 1));
        });

        details.appendChild(summary);
        details.appendChild(childrenContainer);
        container.appendChild(details);
    } else {
        // Si pas d'enfant, simple DIV
        container.innerHTML = headerHtml;
    }

    return container;
}
window.renderNode = renderNode;

let lastDecodedJson = null; // Variable interne pour le stockage

window.parseCertificate = async function(pemString) {
    const b64 = pemString.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/[^A-Za-z0-9+/=]/g, "");
    const bytes = new Uint8Array(atob(b64).split("").map(c => c.charCodeAt(0)));
    const asn1 = asn1js.fromBER(bytes.buffer);
    const root = mapASN1toCustomJSON(asn1.result);
    enrichNode(root);
    window.lastDecodedJson = [root]; // On stocke ici
    return window.lastDecodedJson;
};

window.renderNode = renderNode;

window.showJsonModal = function() {
    if (!window.lastDecodedJson) return alert("Veuillez d'abord charger un certificat.");
    const modal = document.getElementById('jsonModal');
    const content = document.getElementById('jsonContent');
    content.innerText = JSON.stringify(window.lastDecodedJson, null, 2);
    modal.classList.remove('hidden');
};

window.hideJsonModal = function() {
    document.getElementById('jsonModal').classList.add('hidden');
};

window.toggleAll = function(isOpen) {
    const allDetails = document.querySelectorAll('#parsingOutput details');
    allDetails.forEach(d => d.open = isOpen);
};
