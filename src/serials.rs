use std::fs;

use xml::reader::{EventReader, XmlEvent};

pub fn parse_serials_file(path: &str) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("{}", e))?;
    parse_serials_content(&content, path)
}

pub fn parse_serials_content(content: &str, path: &str) -> Result<Vec<String>, String> {
    let trimmed = content.trim_start();
    if trimmed.starts_with("<?xml")
        || trimmed.starts_with('<')
        || path.to_lowercase().ends_with(".xml")
    {
        parse_smartpss_xml(content)
    } else {
        Ok(content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect())
    }
}

fn parse_smartpss_xml(content: &str) -> Result<Vec<String>, String> {
    let parser = EventReader::from_str(content);
    let mut serials = Vec::new();
    for event in parser {
        match event {
            Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                if name.local_name == "Device" {
                    let connect = attributes
                        .iter()
                        .find(|a| a.name.local_name == "connect")
                        .map(|a| a.value.trim());
                    if connect == Some("19") {
                        if let Some(domain) = attributes
                            .iter()
                            .find(|a| a.name.local_name == "domain")
                        {
                            let d = domain.value.trim();
                            if !d.is_empty() {
                                serials.push(d.to_string());
                            }
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(e) => return Err(format!("XML parse error: {}", e)),
        }
    }
    Ok(serials)
}

#[cfg(test)]
mod tests {
    use super::parse_serials_content;

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<DeviceManager version="1.0">

<Device connect="19" domain="7H09D4DPAZ7495F" name="01) 7H09D4DPAZ7495F" password="Y2FtdXNlcjAyMjUx" port="37777" protocol="1" username="camuser02251"/>
<Device connect="2" domain="NOT_ME" name="x" port="37777" protocol="1" username="a"/>
<Device domain="NOCONNECT" name="y" port="37777" protocol="1" username="b"/>
<Device connect="19" domain="2K02033PAE00089" name="02) 2K02033PAE00089" password="x" port="37777" protocol="1" username="camuser02251"/>

</DeviceManager>
"#;

    #[test]
    fn parses_domains_with_connect_19() {
        let serials = parse_serials_content(XML, "devices.xml").unwrap();
        assert_eq!(
            serials,
            vec!["7H09D4DPAZ7495F", "2K02033PAE00089"]
        );
    }

    #[test]
    fn parses_plain_lines() {
        let serials =
            parse_serials_content("# comment\n7H09D4DPAZ7495F\n\n2K02033PAE00089\n", "a.txt")
                .unwrap();
        assert_eq!(serials, vec!["7H09D4DPAZ7495F", "2K02033PAE00089"]);
    }

    #[test]
    fn errors_on_xml_extension_with_non_xml_content() {
        let res = parse_serials_content("not xml at all", "devices.xml");
        assert!(res.is_err());
    }
}
