"""recon2win ingestion layer.

    recon2win output → validate → normalize → deduplicate → internal schema

``loader``   locates + reads the raw recon2win files.
``validator`` asserts the upstream contract is present + reports gaps.
``adapter``  maps recon2win rows onto the internal JSAsset schema.
``normalizer`` merges/dedupes by canonical URL and enriches with provenance.
"""
