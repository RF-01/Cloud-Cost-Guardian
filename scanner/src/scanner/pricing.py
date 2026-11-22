"""Cost estimates (design §11.1). STUB until task #21 adds the price table."""


def estimate(resource_type, region, resource):
    """Estimated USD per month for a resource (Decimal), or None when unknown.

    resource_type: "ec2" | "ebs" | "eip"; resource: the raw Describe* dict; extra keys may be added by #21.
    The stub always returns None, so findings are written without estimatedMonthlyCost.
    """
    return None
