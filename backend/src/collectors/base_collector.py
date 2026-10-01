from abc import ABC, abstractmethod

class BaseCollector(ABC):
    def __init__(self, aws_session):
        self.aws = aws_session
        # Pruning of resources that no longer exist (see Scanner.run). A collector opts in
        # by filling existing_ids with EVERY resource id the AWS listing call returned,
        # also ones whose configuration could not be read. listing_complete must be set
        # to False when any part of the listing failed (a region, a page, a describe call
        # needed to know an id), so nothing is pruned on incomplete information.
        self.existing_ids = None
        self.listing_complete = True
        # Regions the listing covered. None = the listing is global (e.g. S3 list_buckets);
        # otherwise pruning only touches stored resources in exactly these regions.
        self.listed_regions = None

    @abstractmethod
    def get_resource_type(self) -> str:
        pass

    @abstractmethod
    def collect(self) -> list:
        pass

    def _resource(self, resource_id, name, region, config):
        return {
            "resource_type": self.get_resource_type(),
            "resource_id":   resource_id,
            "resource_name": name,
            "region":        region,
            "config":        config,
        }