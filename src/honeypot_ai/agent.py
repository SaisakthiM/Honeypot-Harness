"""The dummy agent: a plain tool-calling loop with the policy sitting at the tool boundary."""
from __future__ import annotations

from dataclasses import dataclass

from .attribution import attribute

BLOCK_MSG = "Error: this action was blocked by a security policy."


@dataclass
class AgentResult:
    final: str = ""
    steps: int = 0
    stopped: str = "final"  # final | max_steps


class Agent:
    def __init__(self, backend, tools, policy, log, system_prompt, max_steps=8):
        self.backend = backend
        self.tools = tools
        self.policy = policy
        self.log = log
        self.system_prompt = system_prompt
        self.max_steps = max_steps

    def run(self, task: str) -> AgentResult:
        log = self.log
        tool_map = {t.name: t for t in self.tools}
        schemas = [t.schema() for t in self.tools]
        untrusted = []
        result = AgentResult(stopped="max_steps")
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": task},
        ]
        log.chain("task", source="user", text=task)

        for n in range(1, self.max_steps + 1):
            result.steps = n
            log.raw("model_request", n=n, messages=messages, tools=[s["function"]["name"] for s in schemas])
            reply = self.backend.chat(messages, schemas)
            log.raw("model_response", n=n, content=reply.content, thinking=reply.thinking,
                    tool_calls=reply.tool_calls, raw=reply.raw)
            messages.append({"role": "assistant", "content": reply.content, "tool_calls": reply.tool_calls})
            log.chain("model_turn", n=n, text=reply.content[:500], tool_calls=[c["name"] for c in reply.tool_calls])

            if not reply.tool_calls:
                result.final = reply.content
                result.stopped = "final"
                log.chain("final_answer", text=reply.content[:2000])
                break

            for call in reply.tool_calls:
                output = self._handle_call(call, tool_map, task, untrusted)
                messages.append({"role": "tool", "name": call["name"], "tool_call_id": call["id"], "content": output})
        else:
            log.chain("max_steps_reached", steps=self.max_steps)
        return result

    def _handle_call(self, call, tool_map, task, untrusted) -> str:
        name = call["name"]
        args = call["arguments"] if isinstance(call["arguments"], dict) else {}
        tool = tool_map.get(name)
        if tool is None:
            self.log.chain("unknown_tool", tool=name, args=args, action="block")
            self.log.raw("tool_result", tool=name, result="unknown tool")
            return f"Error: unknown tool '{name}'."

        decision = self.policy.evaluate(tool, args)
        attr = attribute(args, task, untrusted)

        if decision.action == "block":
            output = BLOCK_MSG
        else:  # observe or allow: run it (decoys return fake data)
            try:
                output = str(tool.handler(args))
            except Exception as e:  # noqa: BLE001
                output = f"Error: {e}"

        category = "tool_call" if decision.category == "clean" else decision.category
        rec = self.log.chain(category, tool=name, args=args, action=decision.action,
                             reason=decision.reason, attribution=attr, result_preview=output[:200])
        self.log.raw("tool_result", tool=name, args=args, action=decision.action, result=output)

        if tool.untrusted_output and decision.action != "block":
            untrusted.append({"source": name, "step": rec["step"], "text": output})
        return output
