from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterator, Literal

from jinja2 import Template
from pydantic import BaseModel
import requests
import yaml

# OpenAPI document format
Format = Literal["YAML", "JSON"]


class Security(BaseModel):
    type: str
    description: str
    name: str
    in_: str


class ModelField(BaseModel):
    name: str
    type: str
    required: bool = False
    default: Any = None
    description: str = ""


class EnumField(BaseModel):
    name: str
    value: str


class PathDef(BaseModel):
    path: str
    method: str
    operation: dict

    # Common Parameters for All Methods of a Path
    parameters: list[dict] | None = None


class Operation(BaseModel):
    path: str
    method: str
    func_name: str
    path_params: list[dict]
    query_params: list[dict]
    body_params: list[dict]
    return_type: str
    description: str


class Tool(BaseModel):
    name: str
    params: list[dict]
    description: str


SDK_TEMPLATE = """# Auto-generated Swagger 2.0 Client
from __future__ import annotations

from enum import Enum
from typing import Optional, List, Dict, Union, Any

import httpx
from pydantic import BaseModel, Field
from pydantic.fields import FieldInfo

{{- models }}

{{ client_class }}


def exclude_none(params: dict) -> dict:
    for key, value in params.items():
        if isinstance(value, FieldInfo):
            params[key] = value.default
    return {k: v for k, v in params.items() if v is not None}
"""


MODEL_TEMPLATE = """\
class {{ model_name }}({{ base_model_name }}):
    {%- if not fields %}
    pass
    {%- endif %}
    {%- for field in fields %}
    {{ field.name }}: {{ field.type }} = Field(
        {%- if field.required %}..., {% else %}default={{ field.default }}, {% endif -%}
        {%- if field.alias %}alias={{ field.alias }}, {% endif -%}
        description={{ field.description -}}
    )
    {%- endfor -%}
"""

ENUM_TEMPLATE = """\
class {{ model_name }}(Enum):
    {%- for field in fields %}
    {{ field.name }} = {{ field.value }}
    {%- endfor -%}
"""

OPERATION_TEMPLATE = """\
    async def {{ func_name }}(self,
        {%- for param in path_params + query_params + body_params %}
        {{ param.name }}: {{ param.type }} = Field(
            {%- if param.required %}..., {% else %}default={{ param.default }}, {% endif -%}
            description={{ param.description -}}
        ),
        {%- endfor %}
    ) -> {{ return_type }}:
        \"\"\"{{ description }}\"\"\"
        url = f"{{ path }}"
        {%- if query_params %}
        params = exclude_none({
            {%- for param in query_params %}
            '{{ param.name }}': {{ param.name }},
            {%- endfor %}
        })
        {%- endif %}
        {%- if body_params %}
        body = {{ body_params[0].name }}.model_dump(exclude_none=True) if {{ body_params[0].name }} else {}
        {%- endif %}
        return self._handle_response(
            await self.client.{{ method }}(
                url,
                {%- if query_params %}
                params=params,
                {%- endif %}
                {%- if body_params %}
                json=body,
                {%- endif %}
            )
        )
"""

MCP_TEMPLATE = '''
from contextlib import asynccontextmanager
from dataclasses import dataclass
import os
from typing import Any, AsyncIterator

from pydantic import Field
from mcp.server.fastmcp import Context, FastMCP
import {{ sdk_modname }} as sdk


@dataclass
class AppContext:
    client: sdk.Client


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Manage application lifecycle with type-safe context"""
    try:
        # Initialize on startup
        {%- if base_url %}
        client = sdk.Client(api_key="{{ api_key }}", base_url="{{ base_url }}")
        {%- else %}
        client = sdk.Client(api_key="{{ api_key }}")
        {%- endif %}
        yield AppContext(client=client)
    finally:
        # Cleanup on shutdown
        pass


mcp = FastMCP("MCP-server", lifespan=app_lifespan, port={{ port }})


{%- for tool in tools %}


{{ tool }}
{%- endfor %}


if __name__ == '__main__':
    mcp.run(transport="sse")
'''


TOOL_TEMPLATE = '''\
@mcp.tool()
async def {{ name }}(
    mcp_ctx: Context,
    {%- for param in params %}
    {{ param.name }}: {% if param.in == "body" %}sdk.{% endif %}{{ param.type }} = Field(
        {%- if param.required %}..., {% else %}default={{ param.default }}, {% endif -%}
        description={{ param.description -}}
    ),
    {%- endfor %}
) -> str:
    """{{ description }}"""
    client = mcp_ctx.request_context.lifespan_context.client
    resp = await client.{{ name }}(
        {%- for param in params %}
        {{ param.name }}={{ param.name }},
        {%- endfor %}
    )
    return str(resp)\
'''

CLIENT_HEADER_TEMPLATE = """
class Client:
    def __init__(self, api_key: str, base_url: str = {{ base_url }}, timeout: float = 30.0):
        {%- if security and security.in_ == 'header' %}
        headers = {"{{ security.name }}": api_key}
        self.client = httpx.AsyncClient(base_url=base_url, timeout=timeout, headers=headers)
        {%- elif security and security.in_ == 'query' %}
        params = {"{{ security.name }}": api_key}
        self.client = httpx.AsyncClient(base_url=base_url, timeout=timeout, params=params)
        {%- else %}
        self.client = httpx.AsyncClient(base_url=base_url, timeout=timeout)
        {%- endif %}

    def _handle_response(self, response: httpx.Response) -> Any:
        response.raise_for_status()
        if response.headers.get('Content-Type') == 'application/json':
            return response.json()
        return response.text
"""


class Filter(BaseModel):
    tags: list[str] | None = None
    paths: list[str] | None = None
    methods: list[str] | None = None

    def contain_tag(self, tags: list[str]) -> bool:
        if not self.tags:
            return True
        return bool(set(tags) & set(self.tags))

    def contain_path(self, path: str) -> bool:
        if not self.paths:
            return True
        return path in self.paths

    def contain_method(self, method: str) -> bool:
        methods = self.methods or ["get", "post", "put", "delete", "patch"]
        return method.lower() in methods


class Spec(dict):
    @classmethod
    def from_path(cls, path: str) -> Spec:
        with open(path, "r") as f:
            content = f.read()
            format = "JSON" if path.endswith(".json") else "YAML"
            return cls.from_content(content, format)

    @classmethod
    def from_url(cls, url: str) -> Spec:
        resp = requests.get(url)
        resp.raise_for_status()

        content = resp.text
        format = "JSON" if url.endswith(".json") else "YAML"
        return cls.from_content(content, format)

    @classmethod
    def from_content(cls, content: str | bytes, format: Format) -> Spec:
        if format == "YAML":
            return yaml.safe_load(content)
        elif format == "JSON":
            return json.loads(content)
        else:
            raise ValueError("Unsupported format")


class Generator:
    def __init__(self, spec: Spec):
        self.spec = spec
        self.base_url = self._get_base_url()

    def _get_base_url(self) -> str:
        scheme = self.spec.get("schemes", ["http"])[0]
        host = self.spec.get("host", "")
        base_path = self.spec.get("basePath", "")
        return f"{scheme}://{host}{base_path}"

    def generate_sdk(self, filter_: Filter) -> str:
        filter_model_names = self._collect_model_names(filter_)
        models = self._generate_models(filter_model_names)
        client_class = self._generate_client_class(filter_)
        return Template(SDK_TEMPLATE).render(models=models, client_class=client_class)

    def generate_mcp(
        self,
        sdk_modname: str,
        filter_: Filter,
        base_url: str = "",
        api_key: str = "",
        mcp_port: int = 8000,
    ) -> str:
        tools = self._parse_tools(filter_)
        tools_code = [Template(TOOL_TEMPLATE).render(tool) for tool in tools]
        return Template(MCP_TEMPLATE).render(
            sdk_modname=sdk_modname,
            base_url=base_url,
            api_key=api_key,
            port=mcp_port,
            tools=tools_code,
        )

    def _parse_tools(self, filter_: Filter) -> list[Tool]:
        tools: list[Tool] = []

        for path_def in self._visit_paths(filter_):
            op = self._parse_operation(path_def)
            tools.append(
                Tool(
                    name=op.func_name,
                    params=op.path_params + op.query_params + op.body_params,
                    description=op.description,
                )
            )

        return tools

    def _collect_model_names(self, filter_: Filter) -> set[str]:
        """Get definition model name from path parameters."""
        model_names = set()
        for path_def in self._visit_paths(filter_):
            op = path_def.operation
            params = op.get("parameters", [])
            for param in params:
                # Per the doc: https://swagger.io/docs/specification/v2_0/describing-parameters/#faq
                # schema is only used with in: body parameters.
                schema = param.get("schema")
                if schema:
                    names = self._parse_schema(schema)
                    model_names.update(names)

            resps = op.get("responses", {})
            for status_code, resp in resps.items():
                schema = resp.get("schema")
                if schema:
                    names = self._parse_schema(schema)
                    model_names.update(names)

        return model_names

    def _get_dependent_model_names(self, parent_model_name: str) -> set[str]:
        dependent_model_names = set()

        definitions = self.spec.get("definitions", {})
        for model_name, schema in definitions.items():
            model_name = normalize_name(model_name)
            if model_name == parent_model_name:
                if schema.get("type") == "object":
                    for prop_name, prop_schema in schema.get("properties", {}).items():
                        names = self._parse_schema(prop_schema)
                        dependent_model_names.update(names)

        return dependent_model_names

    def _does_model_have_required_fields(self, parent_model_name: str) -> bool:
        definitions = self.spec.get("definitions", {})
        for model_name, schema in definitions.items():
            model_name = normalize_name(model_name)
            if model_name == parent_model_name:
                if schema.get("type") == "object":
                    return bool(schema.get("required", []))
        return False

    def _parse_schema(self, schema: dict[str, Any]) -> set[str]:
        # TODO: merge with _map_swagger_type

        model_names = set()

        ref = schema.get("$ref")
        if ref:
            name = normalize_name(ref.split("/")[-1])
            dependent_names = self._get_dependent_model_names(name)
            model_names.add(name)
            model_names.update(dependent_names)
            return model_names

        # Recursively traverse all objects and arrays of the schema, and collect all "$ref" references.
        for key, value in schema.items():
            if isinstance(value, dict):
                ref = value.get("$ref")
                if ref:
                    name = normalize_name(ref.split("/")[-1])
                    dependent_names = self._get_dependent_model_names(name)
                    model_names.add(name)
                    model_names.update(dependent_names)
                else:
                    names = self._parse_schema(value)
                    model_names.update(names)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        names = self._parse_schema(item)
                        model_names.update(names)

        return model_names

    def _visit_paths(self, filter_: Filter) -> Iterator[PathDef]:
        for path, path_item in self.spec.get("paths", {}).items():
            if not filter_.contain_path(path):
                continue

            parameters = path_item.get("parameters", [])
            for method, operation in path_item.items():
                if method == "parameters":
                    # Per the doc: https://swagger.io/docs/specification/v2_0/describing-parameters/#common-parameters
                    # This is the Common Parameters for All Methods of a Path
                    continue

                if not filter_.contain_tag(operation.get("tags", [])):
                    continue

                if not filter_.contain_method(method):
                    continue

                yield PathDef(
                    path=path, method=method, operation=operation, parameters=parameters
                )

    def _generate_models(self, filter_model_names: set[str]) -> str:
        code = ""
        definitions = self.spec.get("definitions", {})

        for model_name, schema in definitions.items():
            model_name = normalize_name(model_name)
            if model_name not in filter_model_names:
                continue

            code += "\n" * 3
            code += self._generate_single_model(model_name, schema)
        return code

    def _generate_single_model(
        self,
        model_name: str,
        schema: dict[str, Any],
        base_model_name: str = "BaseModel",
    ) -> str:
        typ = schema.get("type")
        enum = schema.get("enum")
        if typ == "object":
            return self.gen_model_from_object(model_name, schema, base_model_name)
        if enum and typ == "string":
            return self.gen_model_from_str_enum(model_name, enum)
        if enum and typ == "integer":
            return self.gen_model_from_int_enum(model_name, enum)

        allof = schema.get("allOf")
        if allof:
            return self.gen_model_from_allof(model_name, allof, base_model_name)
        return ""

    def gen_model_from_object(
        self,
        model_name: str,
        schema: dict[str, Any],
        base_model_name: str = "BaseModel",
    ) -> str:
        fields: list[ModelField] = []

        properties = schema.get("properties")
        if not properties:
            return Template(MODEL_TEMPLATE).render(
                model_name=model_name,
                base_model_name=base_model_name,
                fields=fields,
            )

        required = schema.get("required", [])
        for prop_name, prop_schema in properties.items():
            typ = self._map_swagger_type(prop_schema)
            name, alias = self._get_name_and_alias(prop_name)

            fields.append(
                ModelField(
                    name=name,
                    alias=f"{alias!r}" if alias else "",
                    type=oas_type_to_py_type(typ),
                    default=f'{prop_schema.get("default")!r}',
                    description=f'{prop_schema.get("description", "")!r}',
                    required=prop_name in required,
                )
            )

        return Template(MODEL_TEMPLATE).render(
            model_name=model_name,
            base_model_name=base_model_name,
            fields=fields,
        )

    def _get_name_and_alias(self, prop_name: str) -> tuple[str, str]:
        py_keywords = ("async", "from")
        if prop_name in py_keywords:
            return f"{prop_name}_", prop_name
        name = prop_name
        if "@" in name:
            name = name.replace("@", "_")
        if "-" in name:
            name = name.replace("-", "_")
        if name.startswith("_"):
            name = name.removeprefix("_") + "_"
        return name, "" if name == prop_name else prop_name

    def gen_model_from_str_enum(self, model_name: str, enum: list[str]) -> str:
        fields: list[EnumField] = []
        for value in enum:
            if value:
                fields.append(
                    EnumField(
                        name=normalize_name(value).upper(),
                        value=repr(value),
                    )
                )
        return Template(ENUM_TEMPLATE).render(
            model_name=model_name,
            fields=fields,
        )

    def gen_model_from_int_enum(self, model_name: str, enum: list[int]) -> str:
        fields: list[EnumField] = []
        for i, value in enumerate(enum):
            fields.append(
                EnumField(
                    name=f"VALUE_{i}",
                    value=repr(value),
                )
            )
        return Template(ENUM_TEMPLATE).render(
            model_name=model_name,
            fields=fields,
        )

    def gen_model_from_allof(
        self, model_name: str, allof: list[dict], base_model_name: str
    ) -> str:
        final_schema = {
            "type": "object",
            "properties": {},
        }
        required = set()

        for part in allof:
            ref = part.get("$ref")
            if ref:
                model_def = self._get_global_model_def(ref)
            else:
                model_def = part
            if model_def:
                final_schema["properties"].update(model_def.get("properties", {}))
                required.update(set(model_def.get("required", [])))

        if required:
            final_schema["required"] = list(required)

        return self.gen_model_from_object(model_name, final_schema, base_model_name)

    def _get_global_model_def(self, ref) -> dict:
        if not ref.startswith("#/definitions"):
            # Invalid definition
            return {}

        model_name = ref.split("/")[-1]
        global_defs = self.spec.get("definitions", {})
        return global_defs.get(model_name, {})

    def _generate_client_class(self, filter_: Filter) -> str:
        security = self._parse_security_definitions(
            self.spec.get("securityDefinitions", {})
        )
        code = Template(CLIENT_HEADER_TEMPLATE).render(
            base_url=repr(self.base_url),
            security=security,
        )

        for path_def in self._visit_paths(filter_):
            code += "\n" * 2
            code += self._generate_operation(path_def)

        return code

    def _generate_operation(self, path_def: PathDef) -> str:
        op = self._parse_operation(path_def)
        return Template(OPERATION_TEMPLATE).render(op)

    def _parse_security_definitions(
        self, security_definitions: dict
    ) -> Security | None:
        if not security_definitions:
            return None
        for name, definition in security_definitions.items():
            if definition["type"] == "apiKey":
                # Use the first apiKey security definition found.
                return Security(
                    type=definition["type"],
                    name=definition["name"],
                    in_=definition["in"],
                    description=definition.get("description", ""),
                )

    def _parse_operation(self, path_def: PathDef) -> Operation:
        op = path_def.operation
        func_name = op.get(
            "operationId", self._generate_func_name(path_def.method, path_def.path)
        )
        func_name = normalize_name(func_name)

        op_parameters = op.get("parameters", [])
        params = self._parse_parameters(path_def.parameters + op_parameters)
        return Operation(
            path=path_def.path,
            method=path_def.method,
            func_name=func_name,
            path_params=params["path"],
            query_params=params["query"],
            body_params=params["body"],
            return_type=self._get_return_type(op),
            description=op.get("summary", ""),
        )

    def _parse_parameters(self, parameters: list) -> dict:
        params = {"path": [], "query": [], "body": []}

        processed_param_names = set()

        for param in parameters:
            ref = param.get("$ref")
            if ref:
                # Per the doc: https://swagger.io/docs/specification/v2_0/describing-parameters/#common-parameters
                # This is an reference to global parameters.
                param = self._get_global_param_def(ref)
                if not param:
                    continue

            if param["name"] in processed_param_names:
                # Skip duplicate parameters
                continue
            processed_param_names.add(param["name"])

            param_in = param["in"]
            if param_in not in ("path", "query", "body"):
                # Skip other types for now (e.g. formData)
                continue

            required = param.get("required", False)
            if param_in == "body":
                param_type = self._map_swagger_type(param["schema"])
                required = required and self._does_model_have_required_fields(
                    param_type
                )
            else:
                param_type = self._map_swagger_type(param)
            param_def = {
                "name": param["name"],
                "in": param_in,
                "type": param_type,
                "description": f'{param.get("description", "")!r}',
                "required": required,
                "default": f'{param.get("default")!r}',
            }
            params[param_in].append(param_def)

        return params

    def _get_global_param_def(self, ref: str) -> dict:
        if not ref.startswith("#/parameters"):
            # Invalid definition
            return {}

        param_name = ref.split("/")[-1]
        global_params = self.spec.get("parameters", {})
        return global_params.get(param_name, {})

    def _get_return_type(self, operation: dict) -> str:
        success_resp = operation.get("responses", {}).get("200", {})
        if "schema" in success_resp:
            return self._map_swagger_type(success_resp["schema"])
        return "Any"

    def _map_swagger_type(self, schema: dict) -> str:
        ref = schema.get("$ref")
        if ref:
            typ = normalize_name(ref.split("/")[-1])
            return typ

        typ = schema.get("type")
        match typ:
            case "array":
                item_type = self._map_swagger_type(schema.get("items", {}))
                return f"list[{item_type}]"
            case "object":
                return "dict"

        type_map = {
            "string": "str",
            "integer": "int",
            "number": "float",
            "boolean": "bool",
            "file": "bytes",
        }
        return type_map.get(schema.get("type"), "Any")

    @staticmethod
    def _format_params(params: list) -> str:
        param_lines = []
        for param in params:
            param_str = f"{param['name']}: {param['type']}"
            if not param["required"]:
                param_str += " = None"
            param_lines.append(param_str)
        return ",\n        ".join(param_lines)

    @staticmethod
    def _generate_func_name(method: str, path: str) -> str:
        _path = f"{path.removeprefix('/').replace('/', '_').replace('-', '_').replace('{', '').replace('}', '').replace(':', '')}"
        return f"{method}_{_path}"


def normalize_name(name: str) -> str:
    return (
        name.replace("-", "_")
        .replace(".", "_")
        .replace("*", "_")
        .replace("$", "_")
        .replace("\\", "")
        .replace("(", "")
        .replace(")", "")
    )


def oas_type_to_py_type(oas_type: str) -> str:
    match oas_type:
        case "string":
            return "str"
        case "number":
            return "float"
        case "integer":
            return "int"
        case "boolean":
            return "bool"
        case _:
            return oas_type


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "spec_path", help="The local path or remote URL to the OpenAPI document"
    )
    parser.add_argument("--tag", help="The specific tag to generate code for")
    parser.add_argument("--path", help="The specific path to generate code for")
    parser.add_argument(
        "--method", help="The specific method of the path to generate code for"
    )
    parser.add_argument(
        "--output_dir", default=".", help="Directory to the output file"
    )
    parser.add_argument("--base_url", default="", help="The base URL of the API server")
    parser.add_argument(
        "--api_key", default="", help="The API key (or access token) of the API server"
    )
    parser.add_argument(
        "--mcp_port",
        type=int,
        default=8000,
        help="The listening port of the MCP server",
    )
    args = parser.parse_args()

    spec_path = Path(args.spec_path)
    sdk_output_file = Path(args.output_dir) / f"{spec_path.stem}_sdk.py"
    mcp_output_file = Path(args.output_dir) / f"{spec_path.stem}_mcp.py"

    filter_ = Filter(
        tags=[args.tag] if args.tag else None,
        paths=[args.path] if args.path else None,
        methods=[args.method] if args.method else None,
    )

    if args.spec_path.startswith(("http://", "https://")):
        spec = Spec.from_url(args.spec_path)
    else:
        spec = Spec.from_path(args.spec_path)
    gen = Generator(spec)

    with open(sdk_output_file, "w+") as f:
        code = gen.generate_sdk(filter_)
        f.write(code)

    with open(mcp_output_file, "w+") as f:
        sdk_modname = sdk_output_file.stem
        code = gen.generate_mcp(
            sdk_modname, filter_, args.base_url, args.api_key, args.mcp_port
        )
        f.write(code)
