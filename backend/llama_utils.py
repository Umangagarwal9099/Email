from llama_cpp import Llama

# Load your LLaMA 3.2 1B model
llm = Llama(
    model_path="models/llama-3.2-3b-instruct-q4_k_m.gguf",
    n_ctx=1024,
    n_threads=6,
    n_gpu_layers=0,
    verbose=False
)


def generate_llama_response(prompt: str, max_tokens=64):
    output = llm(
        prompt=prompt,
        max_tokens=max_tokens,
        temperature=0.1,
        top_p=0.9,
        stop=["\n", "User:", "Answer:"]
    )
    return output["choices"][0]["text"].strip()

def classify_email_tone(email_text: str) -> str:
    prompt = (
        "You are a tone classifier. Respond with one word: polite, urgent, neutral, or formal.\n\n"
        "Email: Please let me know your feedback at your convenience.\nAnswer: polite\n"
        "Email: I need this done immediately!\nAnswer: urgent\n"
        "Now i need you to answer about the email below:\n"
        f"Email: {email_text.strip()}\nAnswer:"
    )
    result = generate_llama_response(prompt, max_tokens=8).lower()
    print("[Tone Raw]:", repr(result))
    for tone in ["polite", "urgent", "neutral", "formal"]:
        if tone in result:
            return tone
    return f"unknown ({result})"

def detect_spam(email_text: str) -> bool:
    prompt = (
        "You are a spam detector. Respond only with 'yes' or 'no'.\n\n"
        "Email: You've won a free prize! Click this link to claim.\nAnswer: yes\n"
        "Email: Let's schedule a meeting for next week.\nAnswer: no\n"
        "Now i need you to answer about the email below:\n"
        f"Email: {email_text.strip()}\nAnswer:"
    )
    result = generate_llama_response(prompt, max_tokens=5).lower()
    print("[Spam Raw]:", repr(result))
    return "yes" in result
