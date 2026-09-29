"""Render a public research question with its predecessor and job nonce."""

def render(template, predecessor_hex, nonce_hex):
    if len(predecessor_hex)!=64 or len(nonce_hex)!=64:
        raise ValueError('predecessor and nonce must be 32-byte hex')
    bytes.fromhex(predecessor_hex);bytes.fromhex(nonce_hex)
    return (template + '\nThis job is bound to predecessor ' + predecessor_hex +
            ' and nonce ' + nonce_hex +
            '. These bytes are context, not part of the target theorem.\n')
