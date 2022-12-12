# Networking-Project
# Networking-Project
For running XSS attack follow below steps:
  a. docker pull ghavan/xss-attack
  b. docker run -p 4000:80 -it ghavan/xss-attack
      You will be asked to enter URL, so you can pass two urls one having vulnerabilities and one       having no vulnerabilities.
      i) http://php.testsparker.com/process.php?file=Generics/index.nsp (NOT VULNERABLE)
      ii) http://php.testsparker.com/products.php?pro=url (VULNERABLE)
