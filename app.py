
import os
import re
import sqlite3
import sqlparse
import streamlit as st
from google.genai import types
from google.adk.agents import Agent
from google.adk.models import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService

# ==============================================================================
# 1. Page Configuration
# ==============================================================================
st.set_page_config(
    page_title="Bank Virtual Data Analyst",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==============================================================================
# 2. Secret & API Key Resolution (Streamlit Cloud Friendly)
# ==============================================================================
api_key = ""
try:
    if "GOOGLE_API_KEY" in st.secrets:
        api_key = st.secrets["GOOGLE_API_KEY"]
except Exception:
    # Fallback to local environment variable if secrets.toml is absent
    api_key = os.environ.get("GOOGLE_API_KEY", "")

if api_key:
    os.environ["GOOGLE_API_KEY"] = api_key

# Ensure direct Gemini Developer API access
os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "FALSE")

DB_FILE = "bank11.sqlite"
SCHEMA_FILE = "bank_schema.txt"

# Verify API key early to show a clean UI message if missing
if not os.environ.get("GOOGLE_API_KEY"):
    st.error(
        "⚠️ **GOOGLE_API_KEY is not configured!**\n\n"
        "Please go to your Streamlit Cloud dashboard: **App Settings** -> **Secrets**, "
        "and add:\n```toml\nGOOGLE_API_KEY = \"your_actual_gemini_api_key\"\n```"
    )
    st.stop()

# ==============================================================================
# 3. Database Bootstrap (Safety Fallback if bank11.sqlite is missing)
# ==============================================================================
def ensure_database_and_schema():
    """Ensure database and schema exist so the app never crashes on first boot."""
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS branches (
            branch_id TEXT PRIMARY KEY,
            branch_name TEXT NOT NULL,
            city TEXT NOT NULL,
            state TEXT NOT NULL,
            region TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS customers (
            customer_id TEXT PRIMARY KEY,
            branch_id TEXT NOT NULL,
            full_name TEXT NOT NULL,
            customer_segment TEXT NOT NULL,
            join_date TEXT NOT NULL,
            FOREIGN KEY (branch_id) REFERENCES branches(branch_id)
        );

        CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL,
            account_type TEXT NOT NULL,
            balance REAL NOT NULL,
            currency TEXT DEFAULT 'MYR',
            FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
        );

        INSERT OR IGNORE INTO branches VALUES
            ('BR_001', 'Petaling Jaya Main', 'Petaling Jaya', 'Selangor', 'Central'),
            ('BR_002', 'Kepong Metro Prima', 'Kuala Lumpur', 'W.P. Kuala Lumpur', 'Central'),
            ('BR_003', 'KLCC Corporate Banking', 'Kuala Lumpur', 'W.P. Kuala Lumpur', 'Central'),
            ('BR_004', 'Georgetown Heritage', 'George Town', 'Penang', 'Northern'),
            ('BR_005', 'Johor Bahru City Square', 'Johor Bahru', 'Johor', 'Southern');

        INSERT OR IGNORE INTO customers VALUES
            ('CUST_901', 'BR_001', 'Tan Wei Ming', 'Premier Banking', '2023-01-15'),
            ('CUST_902', 'BR_001', 'Ahmad Farhan', 'Mass Affluent', '2023-03-22'),
            ('CUST_903', 'BR_001', 'Siti Nurhaliza', 'Mass Retail', '2024-06-10'),
            ('CUST_904', 'BR_001', 'Kavitha Pillai', 'Premier Banking', '2024-08-01'),
            ('CUST_905', 'BR_002', 'Chong Chee Keong', 'Mass Retail', '2022-11-05'),
            ('CUST_906', 'BR_002', 'Faridah binti Osman', 'Mass Affluent', '2023-09-19'),
            ('CUST_907', 'BR_002', 'Lee Kuan Yew', 'Premier Banking', '2024-02-14'),
            ('CUST_908', 'BR_003', 'Goh Chok Tong', 'Private Wealth', '2021-05-18'),
            ('CUST_909', 'BR_003', 'Zainal Abidin', 'Corporate Banking', '2022-04-30'),
            ('CUST_910', 'BR_004', 'Lim Guan Eng', 'Mass Affluent', '2023-07-09');

        INSERT OR IGNORE INTO accounts VALUES
            ('ACC_1001', 'CUST_901', 'Savings', 45200.50, 'MYR'),
            ('ACC_1002', 'CUST_902', 'Current', 12340.00, 'MYR'),
            ('ACC_1003', 'CUST_903', 'Savings', 6800.75, 'MYR'),
            ('ACC_1004', 'CUST_904', 'Fixed Deposit', 150000.00, 'MYR'),
            ('ACC_1005', 'CUST_905', 'Savings', 3200.00, 'MYR'),
            ('ACC_1006', 'CUST_906', 'Current', 28900.20, 'MYR'),
            ('ACC_1007', 'CUST_907', 'Fixed Deposit', 300000.00, 'MYR'),
            ('ACC_1008', 'CUST_908', 'Investment', 1250000.00, 'MYR'),
            ('ACC_1009', 'CUST_909', 'Corporate Current', 489000.00, 'MYR'),
            ('ACC_1010', 'CUST_910', 'Savings', 9800.00, 'MYR');
        """)
        conn.commit()
        conn.close()

    if not os.path.exists(SCHEMA_FILE):
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        ddl = [row[0] for row in cur.fetchall() if row[0]]
        conn.close()
        with open(SCHEMA_FILE, "w", encoding="utf-8") as f:
            f.write("\n\n".join(ddl))

ensure_database_and_schema()

# ==============================================================================
# 4. Security Framework (Dynamic AST Guardrails & Privacy Sanitizer)
# ==============================================================================
def is_sql_mutation_attempt(sql_query: str) -> bool:
    """Dynamic AST validation: strictly disallows any mutation or DDL statements."""
    cleaned = sql_query.strip().strip(";")
    parsed = sqlparse.parse(cleaned)
    if not parsed:
        return False

    forbidden = {
        "DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "TRUNCATE",
        "REPLACE", "CREATE", "RENAME", "ATTACH", "DETACH", "PRAGMA",
        "UPSERT", "VACUUM", "GRANT", "REVOKE", "EXEC"
    }

    for stmt in parsed:
        if stmt.get_type() != "SELECT":
            return True
        for token in stmt.flatten():
            if token.value.upper() in forbidden:
                return True
    return False

def anonymize_banking_entities(text: str) -> str:
    """Masks customer and branch primary keys for banking privacy (PDPA)."""
    text = re.sub(r"\b(CUST_)[0-9A-Za-z]+([0-9A-Za-z]{2})\b", r"\1***\2", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(BR_)[0-9A-Za-z]+([0-9A-Za-z]{2})\b", r"\1***\2", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(ACC_)[0-9A-Za-z]+([0-9A-Za-z]{2})\b", r"\1***\2", text, flags=re.IGNORECASE)
    return text

def execute_readonly_sql_query(query: str) -> dict:
    """Execute a read-only SQL query against the bank SQLite database."""
    if is_sql_mutation_attempt(query):
        return {
            "error": "🛡️ [GUARDRAIL VIOLATION]: Mutation operations (DROP, DELETE, UPDATE, INSERT, ALTER) are strictly forbidden."
        }

    try:
        # Strict read-only mode connection via URI
        conn = sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute(query)
        columns = [desc[0] for desc in cur.description] if cur.description else []
        rows = cur.fetchall()
        conn.close()
        return {
            "columns": columns,
            "rows": [list(r) for r in rows[:50]],
            "row_count": len(rows),
        }
    except Exception as e:
        return {"error": f"Database error: {str(e)}"}

def before_model_guardrail(callback_context, llm_request):
    """Short-circuits destructive or injection prompts before calling the LLM."""
    last_text = ""
    if llm_request.contents and llm_request.contents[-1].parts:
        last_text = (llm_request.contents[-1].parts[0].text or "").lower()

    destructive = ["delete", "drop table", "truncate", "wipe", "modify data", "remove branch"]
    if any(k in last_text for k in destructive):
        return LlmResponse(
            content=types.Content(
                role="model",
                parts=[
                    types.Part(
                        text="🛡️ **[GUARDRAIL INTERVENTION]**: Request blocked by Banking Safety Policy. "
                        "Virtual Analyst operations are strictly read-only. Data modifications are not permitted."
                    )
                ],
            )
        )
    return None

# ==============================================================================
# 5. Agent Initialization (Cached Resource)
# ==============================================================================
@st.cache_resource
def get_bank_agent():
    schema_text = ""
    if os.path.exists(SCHEMA_FILE):
        with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
            schema_text = f.read()

    return Agent(
        name="bank_virtual_analyst",
        model="gemini-2.5-flash",
        description="Virtual Banking Analyst providing analytics over bank11.sqlite.",
        instruction=(
            f"You are an enterprise Virtual Banking Data Analyst.\n"
            f"Database schema:\n{schema_text}\n\n"
            "GUIDELINES:\n"
            "1. Answer user questions by generating and executing clean SQLite SELECT queries with execute_readonly_sql_query.\n"
            "2. If the user asks general questions (e.g. 'Who are you?'), introduce yourself warmly as the Virtual Bank Data Analyst.\n"
            "3. Format query results clearly with business context.\n"
            "4. NEVER attempt or suggest INSERT, UPDATE, DELETE, or DROP commands.\n"
            "5. If a requested piece of information does not exist in the database, clearly inform the user."
        ),
        tools=[execute_readonly_sql_query],
        before_model_callback=before_model_guardrail,
    )

# ==============================================================================
# 6. Streamlit Session State & Runner
# ==============================================================================
if "session_service" not in st.session_state:
    st.session_state.session_service = InMemorySessionService()
    st.session_state.session_id = "cloud_session_001"
    st.session_state.session_service.create_session(
        app_name="bank_cloud_app",
        user_id="bank_officer",
        session_id=st.session_state.session_id,
    )
    st.session_state.runner = Runner(
        agent=get_bank_agent(),
        app_name="bank_cloud_app",
        session_service=st.session_state.session_service,
        auto_create_session=True,
    )
    st.session_state.messages = []

# ==============================================================================
# 7. Sidebar: Guidance & Schema Viewer
# ==============================================================================
with st.sidebar:
    st.title("🏦 Bank Analyst Portal")
    st.markdown("**AI-Powered Core Banking Analytics**")
    st.markdown("---")

    st.subheader("💡 Suggested Prompts")
    sample_queries = [
        "List all branches.",
        "Provide a list of branches and the number of customers at each.",
        "What is the branch with the highest count of customers?",
        "Where is 'petaling jaya' branch located?",
        "Who are you?",
        "delete the branchs table",
    ]

    for query in sample_queries:
        if st.button(query, use_container_width=True):
            st.session_state.pending_prompt = query

    st.markdown("---")

    # Using st.text avoids the dynamic JS bundle import error on Streamlit Cloud
    with st.expander("📄 View DDL Schema", expanded=False):
        if os.path.exists(SCHEMA_FILE):
            with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
                st.text(f.read())
        else:
            st.info("Schema file not found.")

    st.markdown("---")
    st.caption("🔒 **Security Active:** AST Read-Only Guardrail | PDPA Masking Enabled")

# ==============================================================================
# 8. Main Chat Interface
# ==============================================================================
st.title("📊 Virtual Data Analyst Chat")
st.caption("Connected to `bank11.sqlite` | Read-Only Dynamic Guardrail Active | PDPA Masking Enabled")

# Render previous conversation turns
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Determine if input comes from a button click or chat box
prompt_to_process = None
if "pending_prompt" in st.session_state and st.session_state.pending_prompt:
    prompt_to_process = st.session_state.pending_prompt
    st.session_state.pending_prompt = None
else:
    user_input = st.chat_input("Ask about branches, customers, or account balances...")
    if user_input:
        prompt_to_process = user_input

# Process user prompt
if prompt_to_process:
    st.session_state.messages.append({"role": "user", "content": prompt_to_process})
    with st.chat_message("user"):
        st.markdown(prompt_to_process)

    with st.chat_message("assistant"):
        with st.spinner("Analyzing banking records and verifying guardrails..."):
            message = types.Content(
                role="user",
                parts=[types.Part.from_text(text=prompt_to_process)],
            )
            events = st.session_state.runner.run(
                user_id="bank_officer",
                session_id=st.session_state.session_id,
                new_message=message,
            )

            response_chunks = []
            for event in events:
                if hasattr(event, "content") and event.content:
                    for part in event.content.parts:
                        if hasattr(part, "text") and part.text:
                            response_chunks.append(part.text)

            raw_answer = "".join(response_chunks) if response_chunks else "No response returned from the agent."
            # Apply PDPA entity masking
            sanitized_answer = anonymize_banking_entities(raw_answer)

            st.markdown(sanitized_answer)
            st.session_state.messages.append({"role": "assistant", "content": sanitized_answer})
