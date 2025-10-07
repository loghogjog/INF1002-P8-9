# Test cases built with the help of ChatGPT. Thank You GPT <3
import os, sys
import pytest
from email import policy
from email.parser import BytesParser
# Path to root folder
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from modules.attachment_scanner import mime_type_check, attachment_evaluation  # replace with your actual import

# Path to your folder of .eml samples
TEST_FOLDER = os.path.join(os.path.dirname(__file__), "..", "attachments_test_samples")

def extract_attachments_from_eml(eml_path):
    """
    Parse an EML file and extract all attachments as tuples:
    (filename, extension, binary_data)
    """
    attachments = []
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    for part in msg.iter_attachments():
        filename = part.get_filename()
        if not filename:
            continue  # skip inline or nameless parts

        ext = os.path.splitext(filename)[1].lstrip(".").lower()
        data = part.get_payload(decode=True)
        attachments.append((filename, ext, data))
    return attachments


@pytest.mark.parametrize("filename", [
    f for f in os.listdir(TEST_FOLDER)
    if f.lower().endswith(".eml")
])
def test_mime_type_check_eml_attachments(filename):
    """
    Reads all EML files in attachments_test_samples, extracts attachments,
    and runs them through mime_type_check.
    """
    eml_path = os.path.join(TEST_FOLDER, filename)
    attachments = extract_attachments_from_eml(eml_path)

    assert attachments, f"{filename} has no attachments to test."

    for attach_name, ext, data in attachments:
        print(f"\n📄 Testing attachment: {attach_name} from {filename}")
        result = mime_type_check(attach_name, ext, data)
        print(f"→ Result: {result}")

        # --- Expected Result Rules ---
        # You can expand or customize this section based on known samples
        suspicious_keywords = ("vbscript", "powershell", "js", "script")
        if any(k in attach_name.lower() for k in suspicious_keywords):
            assert result is False or result is None, f"{attach_name} should be suspicious."
        else:
            # Default: must pass MIME check
            assert result is True, f"{attach_name} should be valid."

        # Test double extension check too
        #test_attachment_scan(filename)


def test_all_eml_files_have_valid_structure():
    """
    Ensures all .eml files in the test directory are parseable.
    """
    for f in os.listdir(TEST_FOLDER):
        if not f.lower().endswith(".eml"):
            continue
        path = os.path.join(TEST_FOLDER, f)
        with open(path, "rb") as eml_file:
            try:
                msg = BytesParser(policy=policy.default).parse(eml_file)
            except Exception as e:
                pytest.fail(f"Failed to parse {f}: {e}")



#def test_attachment_scan(eml_path):
#    # Assert Attachments
#    # Assert Double Extension Check
#    assert attachments, f"{eml_path} has no attachments to test."
#
#    for results in attachment_evaluation(attachments):
#        if "attachment" in results['rule'].lower() and not results['rule'] ==  "No Attachments Found" and not "Unknown" in results['rule']:
#            attachment_name = results['rule'].split(' - ')[1]
#            if len(attachment_name.split('.')) > 2:
#                assert "Double Extension Check Fail" in results['reasons']
#            else: 
#                assert "Double Extension Check Pass" in results['reasons']