from flask import Flask, request, redirect, url_for, session, render_template, flash, send_file, make_response
import pdfkit
from authlib.integrations.flask_client import OAuth
import psycopg2
import bcrypt  # Import bcrypt for password hashing

app = Flask(__name__)
app.secret_key = '7c9ba55c0b466dc6bc14b68e5bf5d661'

DATABASE_PARAMS = {
    'dbname': 'IDP',
    'user': 'postgres',
    'password': 'nimish',
    'host': 'localhost',
    'port': '5432'
}

def get_db_connection():
    """Establishes a database connection."""
    return psycopg2.connect(**DATABASE_PARAMS)

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='653068917697-bmsc5j2am2a1floecurglrbq6sft3oq7.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'email profile'}
)

@app.route('/')
def home():
    return redirect(url_for('signup'))

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/submit-your-signup-form-handler', methods=['POST'])
def local_signup():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    
    # Encrypt the password before storing
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    # Store hashed password as a string properly
    hashed_password_str = hashed_password.decode('utf-8')

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO users (name, email, password) VALUES (%s, %s, %s)', (name, email, hashed_password_str))
        conn.commit()
        cur.close()
        conn.close()
        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('login'))
    except Exception as e:
        print(f"Error: {e}")
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('signup'))

@app.route('/submit-your-login-form-handler', methods=['POST'])
def local_login():
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        # Verify the password
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user'] = {'name': user[1], 'email': user[2]}
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed: Invalid credentials', 'danger')
    except Exception as e:
        print(f"Error: {e}")
        flash(f'Error: {e}', 'danger')

    return redirect(url_for('login'))

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()

    session['user'] = user_info
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE email = %s', (user_info['email'],))
        user = cur.fetchone()
        if not user:
            cur.execute('INSERT INTO users (name, email) VALUES (%s, %s)', (user_info['name'], user_info['email']))
            conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error: {e}")
        flash(f'Error: {e}', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    user_info = session.get('user')
    if not user_info:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=user_info)

@app.route('/logout')
def logout():
    session.clear()  # Clears the user's session
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/project-details')
def project_details():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM projects')
    projects = cur.fetchall()
    print(projects)  # Check what is being fetched
    cur.close()
    conn.close()
    return render_template('project_details.html', projects=projects)

@app.route('/submit', methods=['POST'])
def submit_enrollment():
    user_id = request.form['id']
    name = request.form['name']
    course = request.form['course']
    interest = request.form['interest']

    conn = get_db_connection()
    cur = conn.cursor()

    # Check if the user_id already exists in the enrollments
    cur.execute("SELECT * FROM enrollments WHERE user_id = %s", (user_id,))
    if cur.fetchone() is not None:
        flash('Student ID already exists.', 'error')
        return redirect('/enroll')

    # First, check if the selected project has reached its limit
    cur.execute("SELECT COUNT(*) FROM enrollments WHERE interest = %s", (interest,))
    count = cur.fetchone()[0]
    if count >= 21:
        flash('Project limit exceeded, choose another project.', 'error')
        return redirect('/enroll')

    try:
        # If the limit has not been reached, proceed to insert the new enrollment
        cur.execute(
            "INSERT INTO enrollments (user_id, name, course, interest) VALUES (%s, %s, %s, %s)",
            (user_id, name, course, interest)
        )
        conn.commit()
        flash('Enrollment successful!', 'success')
    except Exception as e:
        conn.rollback()
        flash('Enrollment failed: ' + str(e), 'error')
    finally:
        cur.close()
        conn.close()

    return redirect('/enroll')

@app.route('/students')
def students():
    """Displays the students sorted by interest and grouped into teams."""
    course_filter = request.args.get('course')
    interest_filter = request.args.get('interest')
    sort_order = request.args.get('sort', 'asc')  # Default to ascending order

    conn = get_db_connection()
    cur = conn.cursor()

    query = "SELECT user_id, name, course, interest FROM enrollments"
    filters = []
    params = []

    if course_filter:
        filters.append("course = %s")
        params.append(course_filter)

    if interest_filter:
        filters.append("interest = %s")
        params.append(interest_filter)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += " ORDER BY interest " + sort_order

    cur.execute(query, tuple(params))
    students = cur.fetchall()

    teams = {}  # Dictionary to hold teams categorized by interest
    for student in students:
        interest_key = student[3]
        if interest_key not in teams:
            teams[interest_key] = []
        
        placed = False
        for team in teams[interest_key]:
            if len(team) < 8:
                team.append(student)
                placed = True
                break

        if not placed:
            teams[interest_key].append([student])

    # Adjust team sizes to ensure each team has at least 3 members
    for interest, team_groups in teams.items():
        for team in team_groups[:]:
            if len(team) < 3:
                # If a team has fewer than 3 members, attempt to merge with other teams
                for other_team in team_groups:
                    if other_team != team and len(other_team) + len(team) <= 8:
                        other_team.extend(team)
                        team_groups.remove(team)
                        break

    cur.close()
    conn.close()

    return render_template('students.html', teams=teams)

@app.route('/enroll')
def enroll():
    return render_template('enroll.html')



pdfkit_config = pdfkit.configuration(wkhtmltopdf='C:/Program Files/wkhtmltopdf/bin/wkhtmltopdf.exe')

@app.route('/resume_templates')
def resume_templates():
    templates = [
        {'name': 'Template 1', 'filename': 'template1.html'},
        {'name': 'Template 2', 'filename': 'template2.html'},
        {'name': 'Template 3', 'filename': 'template3.html'},
        {'name': 'Template 4', 'filename': 'template4.html'},
        {'name': 'Template 5', 'filename': 'template5.html'}
    ]
    return render_template('resume_templates.html', templates=templates)

@app.route('/resume/<template_name>')
def show_resume_template(template_name):
    return render_template(template_name)

@app.route('/download-pdf', methods=['POST'])
def download_pdf():
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    location = request.form.get('location')
    summary = request.form.get('summary')
    skills = request.form.get('skills')
    education = request.form.get('education')
    work_history = request.form.get('work_history')

    rendered = render_template('pdf_template.html', name=name, email=email, phone=phone, location=location, summary=summary, skills=skills, education=education, work_history=work_history)
    
    pdf = pdfkit.from_string(rendered, False, configuration=pdfkit_config)
    
    response = make_response(pdf)
    
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=resume.pdf'
    
    return response



if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)

