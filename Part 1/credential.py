"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from tkinter import Y
from typing import Any, List, Tuple
import math
from petrelic.multiplicative.pairing import G1, G2, GT

from serialization import jsonpickle


# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = Any
PublicKey = Any
Signature = Any
Attribute = Any
AttributeMap = Any
IssueRequest = Any
BlindSignature = Any
AnonymousCredential = Any
DisclosureProof = Any


######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
    
    L = len(attributes)
    g_1 = G1.generator()
    g_2 = G2.generator()
    x = G1.order().random()
    X_1 = g_1 ** x
    X_2 = g_2 ** x
    y = [ G1.order().random() for i in range(L)]
    Y_1 = [g_1 ** i for i in y] 
    Y_2 = [g_2 ** i for i in y]
    pk = [g_1] + Y_1 + [g_2] + [X_2] + Y_2 
    sk = [x] + [X_1] + y  

    return (sk, pk)


    #raise NotImplementedError()


def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """
    
    h = G1.generator()
    x = sk[0]
    
    return (h , (h ** (x + sum([a*b for a,b in zip(msgs,sk[2:])])) ))
    
    


    #raise NotImplementedError()


def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:
    """ Verify the signature on a vector of messages """
    L = len(msgs)
    s1 = signature[0]
    s2 = signature[1]
    e1 = math.prod([a ** b for a,b in zip (pk[L+3:],msgs)]) * msgs[L+2]
    e2 = pk[L+1]
    
    return ((s1 != G1.neutral_element()) and s1.pair(e1) == s2.pair(e2) )
    #raise NotImplementedError()


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##


def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> IssueRequest:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    L = (len(pk) - 3) / 2 
    t = G1.order().random()
    g = pk[0]
    y = pk[L+3:]
    attributes = [x[0] for x in user_attributes]
    indices = [x[1] for x in user_attributes]
    y = [y[index] for index in indices]
    

    C = (g ** t ) * math.prod(a ** b for a,b in zip (y,attributes))
    return C
    #raise NotImplementedError()


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    u = G1.order().random()
    L = (len(pk) - 3) / 2 
    y = pk[L+3:]
    attributes = [x[0] for x in issuer_attributes]
    indices = [x[1] for x in issuer_attributes]
    y = [y[index] for index in indices]
    
    s_1 = pk[0] ** u
    
    s_2 = (sk[1] * request * math.prod(a ** b for a,b in zip (y,attributes))) ** u

    return(s_1, s_2)
    #raise NotImplementedError()


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    t = G1.order().random()
    return (response[0],response[1].div(response[0]** t))

    #raise NotImplementedError()


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """
    r = G1.order().random()
    t = G1.order().random()
    s = (credential[0]**r,(credential[1]*(credential[0]**t) ** r))
    #PK_1 = s[1].pair()
    #raise NotImplementedError()


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    raise NotImplementedError()
