#!/usr/bin/env python


NAME = 'Cloudfront (Amazon)'


def is_waf(self):
    # This is standard detection schema, checking the server header
    if self.matchheader(('Server', 'Cloudfront')):
        return True
    # Found samples returning 'Via: 1.1 58bfg7h6fg76h8fg7jhdf2.cloudfront.net (CloudFront)'
    if self.matchheader(('Via', r'(.*)?cloudfront.net.+CloudFront.')):
        return True
    # Actual fingerprint is this arising due to attack strings
    for attack in self.attacks:
        r = attack(self)
        if r is None:
            return
        response, page = r
        # The request token is sent along with this header, eg:
        # X-Amz-Cf-Id: sX5QSkbAzSwd-xx3RbJmxYHL3iVNNyXa1UIebDNCshQbHxCjVcWDww==
        if response.getheader('X-Amz-Cf-Id'):
            return True
        # This is another reliable fingerprint found on headers
        if response.getheader('X-Cache') == 'Error from cloudfront':
            return True
        # These fingerprints are found on the blockpage itself
        if any(i in page for i in (b'Generated by cloudfront (CloudFront)', b'The request could not be satisfied')):
            return True
    return False