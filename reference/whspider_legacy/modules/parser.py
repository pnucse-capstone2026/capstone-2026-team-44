from bs4 import BeautifulSoup
from modules.config import TARGET_ATTRIBUTES

def extract_inputs_with_form_context(html: str) -> list:
    soup = BeautifulSoup(html, "html.parser")
    results = []

    form_input_ids = set()
    for form in soup.find_all("form"):
        method = form.get("method", "").upper()
        action = form.get("action", "")
        for tag in form.find_all(["input", "textarea", "select"]):
            if tag.name == "input" and tag.get("type", "").lower() == "hidden":
                continue
            input_info = {
                attr: value
                for attr, value in tag.attrs.items()
                if attr in TARGET_ATTRIBUTES or attr.startswith("aria-")
            }
            if input_info:
                input_info["form_method"] = method
                input_info["form_action"] = action
                results.append(input_info)
            form_input_ids.add(id(tag))

    for tag in soup.find_all(["input", "textarea", "select"]):
        if id(tag) not in form_input_ids:
            if tag.name == "input" and tag.get("type", "").lower() == "hidden":
                continue
            input_info = {
                attr: value
                for attr, value in tag.attrs.items()
                if attr in TARGET_ATTRIBUTES or attr.startswith("aria-")
            }
            if input_info:
                results.append(input_info)

    return results