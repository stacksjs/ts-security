import { describe, it } from 'bun:test'

const ASSERT = require('node:assert')
const forge = require('../../lib/forge')
require('../../lib/pki')
require('../../lib/ssh');

(function () {
  // Original RSA key generated by openssh
  const keystr
    = '-----BEGIN RSA PRIVATE KEY-----\r\n'
      + 'MIIEogIBAAKCAQEA301O+LBnd6ngw9i0Pb5iTwlQ1s37ay3DNpisjh+jPDDvaIZq\r\n'
      + 'PC+44YV7RaR1ib2wEoQfg4DwqVw5wlA2x97Txngb+sJe0yUfmM9vMTxhXWuURVR6\r\n'
      + '6DGd8t2eOBN8qDoYlpvdVf8Go5Btrb6NCexUbZtFS1AmumK2zQKxIizgVLK8dx4G\r\n'
      + 'NYbqxibUxgYHbwRpu8ROrogVrZbMW1cOb4JE+DzG1FvfHSdzkxb9e5ARcsuLxCdP\r\n'
      + 'ItUMVY8jjgER6b5lK+Nzr57hFdr08RjWGBldNGrCFqDdm+1WkGAHTRrg/i/MD8BU\r\n'
      + '8NCFUBpQTSrhALkGqBdGZPN/PrXonXjhcd11awIDAQABAoIBAHGMESUaJnLN2jIc\r\n'
      + 'RoLDBaBk/0tLEJaOfZ6Mgen/InUf+Q0wlGKobZ2Xz3g5SV9SKm8v6gpnjXjBIcmy\r\n'
      + 'GjkGEK/yMWAQaEF7thZxHHxv1J65bnrWm2zolgWCNcsT9aZhbFFhTmpFNO4FKhBY\r\n'
      + 'PcWW+9OESfci+Z57RbL3tHTJVwUZrthtagpFEgVceq18GLSS9N4TWJ8HX1CDxf9R\r\n'
      + '4gzEy3+8oC0QONx+bgsWUmzNk9QNNW6yPV5NYZ3SwNLVgw3+6m8WDaqo5FWK7y2f\r\n'
      + 'pa63DUzXlg5uSYnk4OFVxI6TLpmNQcjigpXnsd1PwcynW0AM83jzIYu0F31ppU61\r\n'
      + '8flrqfECgYEA8j/joUve1F4lTt2U34RF+59giZ1r0ME4LafNEgN/ZLMB8ghToSqr\r\n'
      + 'qzNnJnSppkAKTa2NVZGgJkvqn+qysM1HNm/3ksdUcE5yijgc3E17PNdBJwwNLZfP\r\n'
      + 'p9jB/ZPaNMduGqltYamOVkbg/qS7O4rcUHstrGGGtJ9fveH+cu87emMCgYEA6/oX\r\n'
      + '6A2fW88hw4hZwV2pCk6gumi89vXbKbhnD6j907TW583xIqXYsQBb7x/KGyPf65+k\r\n'
      + 'Sou9MRyLhRu7qcc8INpSnFsra8ZQosP+ao8tUTq7p7N0H27qG5liTeAAksvk/xnq\r\n'
      + '2VdL1YDRpo4tmRD7TAj8uc1sgXqdsBCPrqq4Q1kCgYAHcNjwEmGEymOA+aNh/jEc\r\n'
      + 'Gngfofs2zUiJdncBD6RxFmJ/6auP7ryZJJoNf1XaqmrmmecWcsOliX1qbg4RCi0e\r\n'
      + 'ye+jzYWVcYNpJXIVfjfD1aTFq0QYW2pgcHL88/am2l1SalPWxRt/IOw2Rh8OJCTC\r\n'
      + 'QBZWDiTSFXceYPus0hZUmwKBgCc2FYbfzJ0q3Adrvs5cy9wEmLyg7tVyoQpbs/Rs\r\n'
      + 'NlFZeWRnWixRtqIi1yPy+lhsK6cxjdE9SyDAB4cExrg9fQZQgO2uUJbGC1wgiUQX\r\n'
      + 'qoYW5lvFfARFH+2aHTWnhTDfZJvnKJkY4mcF0tCES5tlsPw/eg89zUvunglFlzqE\r\n'
      + '771xAoGAdYRG1PIkAzjuh785rc35885dsaXChZx1+7rfZ+AclyisRsmES9UfqL6M\r\n'
      + '+SuluaBSWJQUBS7iaHazUeXmy5t+HBjSSLuAOHoZUckwDWD3EM7GHjFlWJOCArI3\r\n'
      + 'hOYlsXSyl07rApzg/t+HxXcNpLZGJTgRwrRGF2OipUL0VPlTdRc=\r\n'
      + '-----END RSA PRIVATE KEY-----\r\n'

  const key = forge.pki.privateKeyFromPem(keystr)

  describe('ssh', () => {
    it('should convert keys to openssh public keys', () => {
      const expect
        = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfTU74sGd3qeDD2LQ9vmJPCVD'
          + 'WzftrLcM2mKyOH6M8MO9ohmo8L7jhhXtFpHWJvbAShB+DgPCpXDnCUDbH3tPGeB'
          + 'v6wl7TJR+Yz28xPGFda5RFVHroMZ3y3Z44E3yoOhiWm91V/wajkG2tvo0J7FRtm'
          + '0VLUCa6YrbNArEiLOBUsrx3HgY1hurGJtTGBgdvBGm7xE6uiBWtlsxbVw5vgkT4'
          + 'PMbUW98dJ3OTFv17kBFyy4vEJ08i1QxVjyOOARHpvmUr43OvnuEV2vTxGNYYGV0'
          + '0asIWoN2b7VaQYAdNGuD+L8wPwFTw0IVQGlBNKuEAuQaoF0Zk838+teideOFx3X'
          + 'Vr A comment'

      ASSERT.equal(forge.ssh.publicKeyToOpenSSH(key, 'A comment'), expect)
    })

    it('should convert keys to putty unencrypted keys', () => {
      const expect
        = 'PuTTY-User-Key-File-2: ssh-rsa\r\n'
          + 'Encryption: none\r\n'
          + 'Comment: imported-openssh-key\r\n'
          + 'Public-Lines: 6\r\n'
          + 'AAAAB3NzaC1yc2EAAAADAQABAAABAQDfTU74sGd3qeDD2LQ9vmJPCVDWzftrLcM2\r\n'
          + 'mKyOH6M8MO9ohmo8L7jhhXtFpHWJvbAShB+DgPCpXDnCUDbH3tPGeBv6wl7TJR+Y\r\n'
          + 'z28xPGFda5RFVHroMZ3y3Z44E3yoOhiWm91V/wajkG2tvo0J7FRtm0VLUCa6YrbN\r\n'
          + 'ArEiLOBUsrx3HgY1hurGJtTGBgdvBGm7xE6uiBWtlsxbVw5vgkT4PMbUW98dJ3OT\r\n'
          + 'Fv17kBFyy4vEJ08i1QxVjyOOARHpvmUr43OvnuEV2vTxGNYYGV00asIWoN2b7VaQ\r\n'
          + 'YAdNGuD+L8wPwFTw0IVQGlBNKuEAuQaoF0Zk838+teideOFx3XVr\r\n'
          + 'Private-Lines: 14\r\n'
          + 'AAABAHGMESUaJnLN2jIcRoLDBaBk/0tLEJaOfZ6Mgen/InUf+Q0wlGKobZ2Xz3g5\r\n'
          + 'SV9SKm8v6gpnjXjBIcmyGjkGEK/yMWAQaEF7thZxHHxv1J65bnrWm2zolgWCNcsT\r\n'
          + '9aZhbFFhTmpFNO4FKhBYPcWW+9OESfci+Z57RbL3tHTJVwUZrthtagpFEgVceq18\r\n'
          + 'GLSS9N4TWJ8HX1CDxf9R4gzEy3+8oC0QONx+bgsWUmzNk9QNNW6yPV5NYZ3SwNLV\r\n'
          + 'gw3+6m8WDaqo5FWK7y2fpa63DUzXlg5uSYnk4OFVxI6TLpmNQcjigpXnsd1Pwcyn\r\n'
          + 'W0AM83jzIYu0F31ppU618flrqfEAAACBAPI/46FL3tReJU7dlN+ERfufYImda9DB\r\n'
          + 'OC2nzRIDf2SzAfIIU6Eqq6szZyZ0qaZACk2tjVWRoCZL6p/qsrDNRzZv95LHVHBO\r\n'
          + 'coo4HNxNezzXQScMDS2Xz6fYwf2T2jTHbhqpbWGpjlZG4P6kuzuK3FB7LaxhhrSf\r\n'
          + 'X73h/nLvO3pjAAAAgQDr+hfoDZ9bzyHDiFnBXakKTqC6aLz29dspuGcPqP3TtNbn\r\n'
          + 'zfEipdixAFvvH8obI9/rn6RKi70xHIuFG7upxzwg2lKcWytrxlCiw/5qjy1ROrun\r\n'
          + 's3QfbuobmWJN4ACSy+T/GerZV0vVgNGmji2ZEPtMCPy5zWyBep2wEI+uqrhDWQAA\r\n'
          + 'AIB1hEbU8iQDOO6Hvzmtzfnzzl2xpcKFnHX7ut9n4ByXKKxGyYRL1R+ovoz5K6W5\r\n'
          + 'oFJYlBQFLuJodrNR5ebLm34cGNJIu4A4ehlRyTANYPcQzsYeMWVYk4ICsjeE5iWx\r\n'
          + 'dLKXTusCnOD+34fFdw2ktkYlOBHCtEYXY6KlQvRU+VN1Fw==\r\n'
          + 'Private-MAC: 87fa1011848453317d8e41b00c927e9d17dc334e\r\n'

      ASSERT.equal(forge.ssh.privateKeyToPutty(key, '', 'imported-openssh-key'), expect)
    })

    it('should convert keys to putty encrypted keys', () => {
      const expect
        = 'PuTTY-User-Key-File-2: ssh-rsa\r\n'
          + 'Encryption: aes256-cbc\r\n'
          + 'Comment: imported-openssh-key\r\n'
          + 'Public-Lines: 6\r\n'
          + 'AAAAB3NzaC1yc2EAAAADAQABAAABAQDfTU74sGd3qeDD2LQ9vmJPCVDWzftrLcM2\r\n'
          + 'mKyOH6M8MO9ohmo8L7jhhXtFpHWJvbAShB+DgPCpXDnCUDbH3tPGeBv6wl7TJR+Y\r\n'
          + 'z28xPGFda5RFVHroMZ3y3Z44E3yoOhiWm91V/wajkG2tvo0J7FRtm0VLUCa6YrbN\r\n'
          + 'ArEiLOBUsrx3HgY1hurGJtTGBgdvBGm7xE6uiBWtlsxbVw5vgkT4PMbUW98dJ3OT\r\n'
          + 'Fv17kBFyy4vEJ08i1QxVjyOOARHpvmUr43OvnuEV2vTxGNYYGV00asIWoN2b7VaQ\r\n'
          + 'YAdNGuD+L8wPwFTw0IVQGlBNKuEAuQaoF0Zk838+teideOFx3XVr\r\n'
          + 'Private-Lines: 14\r\n'
          + 'EiVwpacmA7mhmGBTPXeIZZPkeRDtb4LOWzI+68cA5oM7UJTpBxh9zsnpAdWg2knP\r\n'
          + 'snA5gpTSq0CJV9HWb8yAY3R5izflQ493fCbJzuPFTW6RJ2y/D5dUmDWccfMczPNT\r\n'
          + 'GEDOfslCPe+Yz1h0y0y5NI5WwJowxv3nL9FTlQ9KDVrdoSizkVbTh4CJTrvqIc7c\r\n'
          + 'sI/HU25OHS8kcIZPiPL8m40ot254rkbPCWrskm9H4n+EC+BwJNtEic9ZQfGPWOVl\r\n'
          + 't8JxY35mHqGIlfhyVkdts/Rx7kwOHY+GPXDVRnHQZQOkFtVqCFGx8mL83CspIEq0\r\n'
          + 'V8LaHuvxiadA4OEeR0azuDhfVJXvrUpHd4CPjAzJu4doHm98GJAyrz3mtCyxIguH\r\n'
          + 'k8zKVJzbNawy5T43l5x9cR6VKzcl6d4V14vphiovxc8DG/J7RHBd4d1y6wxo5ZMY\r\n'
          + 'qqQ0E6VHtq6auBZjnGzx0P/1lGjpZdxUf4OVTaZ+stCxX5wAH9exF+gdZAlk20Gp\r\n'
          + 'Atg60boQuolHBiH66dQynyHp+6yuLPLKXy74EO+AEB3HvNK7aIQV8rCD7I7HEa12\r\n'
          + 'xxqIH4l0FWQKHXNIrK45uo6Hdg1siYp9zU4FFgDcNGOZJsT6+etPp1sgAeBuBR4F\r\n'
          + 'pnuX1KZzRTbG1kcRrTOjsMh0bKfZAn0+uwyuPBtwEnLziGoCXU+9+XO85zcPF2j1\r\n'
          + 'Ip5AWAOBI82SKMLu51Dpdz1rwSZOPFWnHxRxfnUiQa9Kc7qBGrMxy1UNECAwMGzp\r\n'
          + 'ljKesqZvoANo0voiodALXGs7kSpmXjcbHnUUt0SI/QHyajXabIiLHGf6lfvStYLP\r\n'
          + 'L5bLfswsMqG/2lonYWrPl9YC0WzvfRpbHgpI9G1eLjFFRlaqJ3EpZf5Dy26Z0eh0\r\n'
          + 'Private-MAC: 23aa5b6e2a411107c59e1e6c3bca06247e3c9627\r\n'

      ASSERT.equal(forge.ssh.privateKeyToPutty(key, 'passphrase', 'imported-openssh-key'), expect)
    })

    it('should convert keys to openssh encrypted private keys', () => {
      const expect
        = '-----BEGIN RSA PRIVATE KEY-----\n'
          + 'Proc-Type: 4,ENCRYPTED\n'
          + 'DEK-Info: AES-128-CBC,2616162F269429AA628E42C3BD5A0027\n'
          + '\n'
          + 'p8+mGWeQxZrRg6OeeFqgEX8sXGGUqWJuK4XhtgRpxAQaSg8bK6m/ahArEonjzgrO\n'
          + 'XMLow7N0aXqGJzL+n4c4EzL7e4SquzeYZLq0UCs8vbWE5GdTT6BxisWIJqzOaQW3\n'
          + 'd3OqS2lM5o47cuADMIMp015b0dJn5nwJall20GSI1XnpTUHIJ1oFv7fW/s5g39VD\n'
          + 'DSVmPzJEMhcTa8BskHrKITV6l+TuivGqrHH0LCYCfQ3IBLiRZrPINQLLkaHR6kis\n'
          + '4qvFEMhQGAz0GrifwEob9+FPzDAHHnYTS0kG1jhZ3p92vaUi8sPxyv5ndRXOSZZg\n'
          + 'vh6Cdrk62myG/rHbsBRrrpa+Ka+BX4ofedwP3SBHPwqBpksYhEF7MxsWKhmHY+d0\n'
          + 'YINHrj0w+yfw4H3n1+0w4wajlHVUncp7RP8KKMtG3vvvfF1loWpLbyF0s6fgq7p4\n'
          + '7kt1LcnRKB3U2IZYfMHuv94+5q0BKfGF6NmRpmgdJojyS2IXZyFaJRqrCa0mKcP9\n'
          + 'PtDZFPTEy0VeNTL8KqjweEmjK3/JtZPVgXXkPWlFMw3Hc/dtP/l6VssGLk8P/DHD\n'
          + 'yknagPsfa70iydTvDO+nrtS57DkoUqhMsU3BhCjMzZg+/bo1JgmxQUWT//PoQLSB\n'
          + 'Z7/F59AfHzZIkWgqfvGRzX3y+G1M1l11dX658iWmN0kZ5MyHU0qwU9hVI6P/fcfk\n'
          + '6MQKc/MzPnkjw/knREtYMtHrVsKrDVDizfguGFKFC8FVhhrDOFZUnza0nh6nt1HZ\n'
          + 'Xk156MhATenWdHBW4Rn3ec1aMOD16k2SRIHd+nyJzx51H3PUdTtXBWqFNGggzoJG\n'
          + '99ax3jD6pTLQY3BG146QKQ0csItMTIdwZPAidkzv8VVXC7HaqXk1K1pgfJT6mD4P\n'
          + 'LaNbuA9r7mNiNoPzwzk0h3BomBTMXZpAyL9Jlre9jTu6lpyN/TkOzHhs/I1/lvKQ\n'
          + 'Uki7BXv65Jq6RqkTbNc5plxBYggdzLGurr0ZIBDsoN6uXkzaM+fCMlJU8+MgAcBb\n'
          + 'x88bj8h3t4akPd/WaSsWKeOzB3Uaw3ztYCpwSVv1F+N0u6C6zGo+9VFAQZh1uKvC\n'
          + 'G9U5hvAG7WEoQ801/fvKj93lqLDhOarPJC8CcfMLwoIqj7zah7TtBYq8VsuF7Fsx\n'
          + 'dEWNFiXhtFqUhgBMt1tcOXGiXA79NucSVzUBNzrRZKlLDYm2TKKyOqEbG9vF/YxL\n'
          + 'ZG3TwmcFj0sko2K61ya7FGpKmfPQCJJoi0tIfnW4eIVcyeRpXYi5B2xqvSXcTdUx\n'
          + '5y5Vpuu1CzrMZr50b3sSOFjcOXE5211RS8SHpOMWY+JDDB4vF4Dv94fqEIgnFtrR\n'
          + 'oQgk3DueWb1x09NcJtEZsW6lT3Jw19ursb++XSejFZ9Xu5ED8fbewgGo2w/N5j1H\n'
          + 'vQEnFkGcL1jLlLqp9PlvPIE4a///wy1y0XbnKMJs+dKxiesKVx1zZ1WDcK2Qgv4r\n'
          + 'G+RsZzHZuCjUyty1+SMVOYM6+3zW6bjXN58xI3XeSxgE/JaJKjLWBZWx5+eU7b6a\n'
          + '04mJDMhnpdLHG97m9p90L1yuudiJfq6ngha41xxv9xLmNatfrtStCrq/DR0KHm0K\n'
          + '-----END RSA PRIVATE KEY-----\n'

      // Unable to test -- uses a random IV that I can't control
      // ASSERT.equal(forge.ssh.rsaPrivateKeyAsOpenSSH(key, 'passphrase'), expect);
    })

    it('should convert keys to openssh unencrypted private keys', () => {
      const expect = keystr
      ASSERT.equal(forge.ssh.privateKeyToOpenSSH(key, ''), expect)
    })

    it('should get an MD5 SSH fingerprint', () => {
      const fp = forge.ssh.getPublicKeyFingerprint(key)
      ASSERT.equal(fp.toHex(), '46549abeb89422a0955d4041ae7322ec')
    })

    it('should get a hex MD5 SSH fingerprint', () => {
      const fp = forge.ssh.getPublicKeyFingerprint(key, { encoding: 'hex' })
      ASSERT.equal(fp, '46549abeb89422a0955d4041ae7322ec')
    })

    it('should get a hex, colon-delimited MD5 SSH fingerprint', () => {
      const fp = forge.ssh.getPublicKeyFingerprint(
        key,
        { encoding: 'hex', delimiter: ':' },
      )
      ASSERT.equal(fp, '46:54:9a:be:b8:94:22:a0:95:5d:40:41:ae:73:22:ec')
    })
  })
})()
