An agent with the scope documents:* can read a contract. It can also delete it. Most agent platforms cannot tell those calls apart at the moment they happen.

The problem: we grant agents scopes once, at registration, then let them act for months. Scopes say what an agent may ever touch, not whether this action, on this record, for this reason, should happen now.

Why it matters: when an agent is steered by injected text, the only thing between the instruction and the damage is the check at the moment of action. Auditors will also ask which rule allowed it and who signed off.

The flow we built:
Intent → Policy → Resource → Authorization → Decision

How it works:
1. Every action an agent may take is registered with a risk tier. Unregistered actions are denied before any policy runs.
2. Before a high-risk action, the agent declares its intent: action, target, justification. The justification is screened for prompt injection and secrets.
3. A human, never the declaring agent, approves the intent. Each approval is good for a fixed number of uses.
4. Resource attributes come from the systems that own them, cached, never from the caller.
5. Policies ship with unit tests. Every rule must decide at least one test, and the author cannot activate their own change.
6. Every decision is logged with the policy digest, including denials.
7. List endpoints get a residual filter they can push into SQL, and the same policies export to Rego for teams running OPA.

Best practices: fail closed when attributes, the policy engine or the audit write are unavailable; keep a kill switch outside policy; validate Entra ID tokens fully, tenant first.

Tradeoffs: a decision per action adds latency; intents add a step for agents; a shared policy service is critical infrastructure and needs high availability.

Value: approvals cover a specific action instead of a broad grant, and an audit question becomes a query.

As agents take on more consequential work, authorization moves from login time to the moment of action.

Question for architects: should an agent ever be allowed to approve another agent's intent?

Code: github.com/kogunlowo123/runtime-authorization-platform

#AI #ArtificialIntelligence #GenerativeAI #AgenticAI #LLMOps #EnterpriseAI #AISecurity #RAG #MachineLearning #DataScience #CloudComputing #Kubernetes #MLOps #DigitalTransformation #Innovation #ZeroTrust #ABAC #OpenPolicyAgent #EntraID
