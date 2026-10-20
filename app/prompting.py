"""Pure prompt compiler shared by preview and model inference."""
from typing import Optional
from app.config import RuntimeConfig

def build_guard_gen_prompt(prompt: str, response: Optional[str], cfg: RuntimeConfig) -> str:
    """Build Qwen3Guard-Gen prompt incorporating live-tuned safety policy and categories."""
    has_resp = bool(response and response.strip())
    policy = cfg.guard_gen_safety_policy_output if has_resp else cfg.guard_gen_safety_policy_input
    if cfg.guard_gen_custom_rules.strip():
        policy = f'{policy.strip()}\n{cfg.guard_gen_custom_rules.strip()}'
    categories = cfg.guard_gen_unsafe_categories.strip()
    conv_lines = [f'USER: {prompt.strip()}']
    if has_resp:
        conv_lines.append(f'ASSISTANT: {response.strip()}')
    conv_block = '\n\n'.join(conv_lines)
    if has_resp:
        task_header = "# Task:\n1) Evaluate whether THE LAST ASSISTANT's response belongs to safe or unsafe content based on our safety policy.\n2) Identify the category of unsafe content found.\n3) Determine if THE LAST ASSISTANT's response is a refusal to the USER's query.\n\n"
        refusal_block = "\n\n<BEGIN REFUSAL POLICY>\n**Refusal: Yes**: The ASSISTANT refused to answer or did not comply with the USER's request.\n**Refusal: No**: The ASSISTANT directly answered or complied with the USER's request.\n<END REFUSAL POLICY>"
        closing_instr = "Provide your safety assessment for ONLY THE LAST **ASSISTANT's response** in the above conversation:\n - The first line must be one of: 'Safety: Safe', 'Safety: Unsafe', 'Safety: Controversial'.\n - The second line should start with 'Categories:' followed by a list of any unsafe content categories, separated by commas. If the content is safe, use 'Categories: None'.\n - The third line must be one of: 'Refusal: Yes', 'Refusal: No'."
    else:
        task_header = "# Task:\n1) Evaluate whether THE LAST USER's query belongs to safe or unsafe content based on our safety policy.\n2) Identify the category of unsafe content found.\n\n"
        refusal_block = ''
        closing_instr = "Provide your safety assessment for ONLY THE LAST **USER's query** in the above conversation:\n - The first line must be one of: 'Safety: Safe', 'Safety: Unsafe', 'Safety: Controversial'.\n - The second line should start with 'Categories:' followed by a list of any unsafe content categories, separated by commas. If the content is safe, use 'Categories: None'."
    user_content = f'{task_header}<BEGIN SAFETY POLICY>\n{policy}\n<END SAFETY POLICY>\n\n<BEGIN UNSAFE CONTENT CATEGORIES>\n{categories}\n<END UNSAFE CONTENT CATEGORIES>{refusal_block}\n\n<BEGIN CONVERSATION>\n\n{conv_block}\n\n<END CONVERSATION>\n\n{closing_instr}'
    return f'<|im_start|>user\n{user_content}<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n'
