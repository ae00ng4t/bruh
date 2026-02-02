mod "azuread_security" {
  title         = "Azure AD Security"
  description   = "Security benchmarks for Azure AD privileged users analysis"
  documentation = file("./docs/index.md")
  
  require {
    plugin "azuread" {
      min_version = "0.1.0"
    }
  }
}
