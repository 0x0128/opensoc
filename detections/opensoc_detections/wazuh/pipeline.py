"""pySigma processing pipeline that maps Sigma field names to Wazuh decoded fields.

The pipeline is generated from ``config/wazuh_mapping.yml``: one field mapping
processing item per supported logsource (conditioned on that logsource), plus
detection-item drops where Wazuh merges records (auditd ``type``).
"""

from __future__ import annotations

from sigma.exceptions import SigmaTransformationError
from sigma.processing.conditions import (
    IncludeFieldCondition,
    LogsourceCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    DropDetectionItemTransformation,
    FieldFunctionTransformation,
)

from opensoc_detections.config import LogsourceMapping, load_mappings

PIPELINE_NAME = "OpenSOC Wazuh field mapping"


def _transform_func(mapping: LogsourceMapping):
    def transform(field: str | None) -> str:
        if field is None:  # keyword detections keep no field name
            return field  # type: ignore[return-value]
        target = mapping.fields.target(field)
        if target is None:
            raise SigmaTransformationError(
                f"Field '{field}' is not mapped for Wazuh logsource '{mapping.id}'. "
                f"Add it to config/wazuh_mapping.yml (known: {', '.join(sorted(mapping.fields.map))})."
            )
        return target

    return transform


def opensoc_wazuh_pipeline() -> ProcessingPipeline:
    items: list[ProcessingItem] = []
    for mapping in load_mappings():
        ls_condition = LogsourceCondition(**mapping.logsource)
        if mapping.fields.drop:
            items.append(
                ProcessingItem(
                    identifier=f"wazuh_{mapping.id}_drop",
                    transformation=DropDetectionItemTransformation(),
                    rule_conditions=[LogsourceCondition(**mapping.logsource)],
                    field_name_conditions=[IncludeFieldCondition(fields=list(mapping.fields.drop))],
                )
            )
        items.append(
            ProcessingItem(
                identifier=f"wazuh_{mapping.id}_fieldmapping",
                transformation=FieldFunctionTransformation(
                    transform_func=_transform_func(mapping), mapping={}
                ),
                rule_conditions=[ls_condition],
            )
        )
    return ProcessingPipeline(
        name=PIPELINE_NAME,
        priority=20,
        items=items,
        allowed_backends=frozenset({"opensoc_wazuh"}),
    )
