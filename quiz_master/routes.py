from app import app
from flask import render_template, request, redirect, url_for, flash, session
from models.models import *
from extensions import db
from werkzeug.security import check_password_hash
from datetime import datetime
from sqlalchemy.sql import func
from dateutil.relativedelta import relativedelta

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        if session.get('user_type') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('login'))

        # Check if it's an admin
        admin = Admin.query.filter_by(email=email).first()
        if admin and check_password_hash(admin.password_hash, password):
            session.clear()
            session['user_id'] = admin.id
            session['user_type'] = 'admin'
            flash('Welcome back, Admin!', 'success')
            return redirect(url_for('admin_dashboard'))

        # If not admin, check if it's a regular user
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session['user_id'] = user.id
            session['user_type'] = 'user'
            flash('Login successful!', 'success')
            return redirect(url_for('user_dashboard'))

        flash('Invalid email or password', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')

def is_valid_password(password):
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    return True

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        if session.get('user_type') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        full_name = request.form.get('fullName')
        email = request.form.get('email')
        qualification = request.form.get('qualification')
        dob = request.form.get('dob')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')

        if not all([full_name, email, qualification, dob, password, confirm_password]):
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('register'))
        
        if not is_valid_password(password):
            flash('Password must be at least 8 characters long and contain uppercase, lowercase, and numbers', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        try:
            new_user = User(
                full_name=full_name,
                email=email,
                qualification=qualification,
                date_of_birth=datetime.strptime(dob, '%Y-%m-%d').date()
            )
            new_user.password = password

            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration', 'warning')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this page', 'warning')
        return redirect(url_for('login'))
    
    total_user = User.query.count()
    total_subjects = Subject.query.count()
    total_quizzes = Quiz.query.count()
    average_score = round(db.session.query(func.avg(Score.score)).scalar() or 0, 2)
    
    search_query = request.args.get('search', '')
    
    if search_query:
        users = User.query.filter(
            db.or_(
                User.full_name.ilike(f'%{search_query}%'),
                User.email.ilike(f'%{search_query}%'),
                User.qualification.ilike(f'%{search_query}%')
            )
        ).order_by(User.id.asc()).all()
    else:
        users = User.query.order_by(User.id.asc()).all()

    return render_template('admin_dashboard.html', 
                         total_user=total_user, 
                         total_subjects=total_subjects, 
                         total_quizzes=total_quizzes, 
                         average_score=average_score, 
                         users=users,
                         search_query=search_query)

@app.route('/update_user/<int:user_id>', methods=['POST'])
def update_user(user_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    
    try:
        if request.form.get('fullName'):
            user.full_name = request.form.get('fullName')
        if request.form.get('email'):
            user.email = request.form.get('email')
        if request.form.get('qualification'):
            user.qualification = request.form.get('qualification')
        if request.form.get('dob'):
            user.date_of_birth = datetime.strptime(request.form.get('dob'), '%Y-%m-%d').date()
        
        db.session.commit()
        flash('User updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating user', 'danger')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
        
    try:
        user = User.query.get_or_404(user_id)
        Score.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)        
        db.session.commit()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user:' + str(e), 'danger')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/subjects')
def admin_subjects():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this page', 'warning')
        return redirect(url_for('login'))
    
    search_query = request.args.get('search', '')
    
    if search_query:
        subjects = Subject.query.filter(
            db.or_(
                Subject.name.ilike(f'%{search_query}%'),
                Subject.description.ilike(f'%{search_query}%'),
            )
        ).order_by(Subject.id.asc()).all()
    else:
        subjects = Subject.query.order_by(Subject.id.asc()).all()
    
    return render_template('admin_subjects.html', subjects=subjects)

@app.route('/add_subject', methods=['POST'])
def add_subject():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
    
    subject_name = request.form.get('subjectName')
    description = request.form.get('description')
    created_by = session['user_id']
    
    if not subject_name or not description:
        flash('Please fill all required fields', 'danger')
        return redirect(url_for('admin_subjects'))
    
    try:
        new_subject = Subject(
            name=subject_name,
            description=description,
            created_by=created_by,
            is_active=True
        )
        db.session.add(new_subject)
        db.session.commit()
        flash('Subject added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding subject: {str(e)}', 'danger')

    return redirect(url_for('admin_subjects'))

@app.route('/update_subject/<int:subject_id>', methods=['POST'])
def update_subject(subject_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
    
    subject = Subject.query.get_or_404(subject_id)

    try:
        if request.form.get('subjectName'):
            subject.name = request.form.get('subjectName')
        if request.form.get('description'):
            subject.description = request.form.get('description')
        db.session.commit()
        flash('Subject updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating subject', 'danger')

    return redirect(url_for('admin_subjects'))

@app.route('/delete_subject/<int:subject_id>', methods=['POST'])
def delete_subject(subject_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
    
    try:
        subject = Subject.query.get_or_404(subject_id)
        # Get all chapters for this subject
        chapters = Chapter.query.filter_by(subject_id=subject_id).all()
        
        # Delete all questions and quizzes for each chapter
        for chapter in chapters:
            # Get all quizzes for this chapter
            quizzes = Quiz.query.filter_by(chapter_id=chapter.id).all()
            
            # Delete questions for each quiz
            for quiz in quizzes:
                Question.query.filter_by(quiz_id=quiz.id).delete()
            
            # Delete all quizzes for this chapter
            Quiz.query.filter_by(chapter_id=chapter.id).delete()
        
        # Delete all chapters for this subject
        Chapter.query.filter_by(subject_id=subject_id).delete()
        db.session.delete(subject)
        db.session.commit()
        flash('Subject deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting subject', 'danger')

    return redirect(url_for('admin_subjects'))

@app.route('/admin/chapters')
def admin_chapters():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this page', 'warning')
        return redirect(url_for('login'))
    
    search_query = request.args.get('search', '')

    if search_query:
        # Search in chapters and include related subjects
        subjects = Subject.query.join(Chapter).filter(
            db.or_(
                Chapter.name.ilike(f'%{search_query}%'),
                Chapter.description.ilike(f'%{search_query}%')
            )
        ).all()
    else:
        # Get all subjects with their chapters
        subjects = Subject.query.all()

    return render_template('admin_chapters.html', subjects=subjects)

@app.route('/add_chapter', methods=['POST'])
def add_chapter():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
    
    subject_id = request.form.get('subjectId')
    chapter_name = request.form.get('chapterName')
    description = request.form.get('description')
    sequence_number = request.form.get('sequenceNumber')
    created_by = session['user_id']

    if not subject_id or not chapter_name or not description or not sequence_number:
        flash('Please fill all required fields', 'danger')
        return redirect(url_for('admin_chapters'))
    
    try:
        new_chapter = Chapter(
            subject_id=subject_id,
            name=chapter_name,
            description=description,
            sequence_number=sequence_number,
            created_by=created_by,
            is_active=True
        )
        db.session.add(new_chapter)
        db.session.commit()
        flash('Chapter added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding chapter: {str(e)}', 'danger')

    return redirect(url_for('admin_chapters'))

@app.route('/update_chapter/<int:chapter_id>', methods=['POST'])
def update_chapter(chapter_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
    
    chapter = Chapter.query.get_or_404(chapter_id)

    try:
        if request.form.get('subjectId'):
            chapter.subject_id = request.form.get('subjectId')
        if request.form.get('chapterName'):
            chapter.name = request.form.get('chapterName')
        if request.form.get('description'):
            chapter.description = request.form.get('description')
        if request.form.get('sequenceNumber'):
            chapter.sequence_number = request.form.get('sequenceNumber')
        db.session.commit()
        flash('Chapter updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating chapter', 'danger')

    return redirect(url_for('admin_chapters'))

@app.route('/delete_chapter/<int:chapter_id>', methods=['POST'])
def delete_chapter(chapter_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
    
    try:
        chapter = Chapter.query.get_or_404(chapter_id)
        # Get all quizzes for this chapter
        quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()
        
        # Delete questions for each quiz
        for quiz in quizzes:
            Question.query.filter_by(quiz_id=quiz.id).delete()
        
        # Delete all quizzes for this chapter
        Quiz.query.filter_by(chapter_id=chapter_id).delete()
        
        db.session.delete(chapter)
        db.session.commit()
        flash('Chapter deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting chapter', 'danger')

    return redirect(url_for('admin_chapters'))

@app.route('/admin/quizzes')
def admin_quizzes():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this page', 'warning')
        return redirect(url_for('login'))
    
    search_query = request.args.get('search', '')
    
    if search_query:
        quizzes = Quiz.query.join(Question, isouter=True).filter(
            db.or_(
                Quiz.title.ilike(f'%{search_query}%'),
                Quiz.description.ilike(f'%{search_query}%'),
                Question.question_text.ilike(f'%{search_query}%'),
            )
        ).distinct().all()
    else:
        quizzes = Quiz.query.order_by(Quiz.date_of_quiz.desc()).all()
    
    subjects = Subject.query.all()
    return render_template('admin_quizzes.html', quizzes=quizzes, subjects=subjects)

@app.route('/add_quiz', methods=['POST'])
def add_quiz():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
    
    try:
        new_quiz = Quiz(
            chapter_id=request.form.get('chapterId'),
            title=request.form.get('title'),
            description=request.form.get('description'),
            date_of_quiz=datetime.strptime(request.form.get('dateOfQuiz'), '%Y-%m-%d'),
            time_duration=request.form.get('timeDuration'),
            passing_score=request.form.get('passingScore'),
            total_marks=request.form.get('totalMarks'),
            created_by=session['user_id'],
            is_active=True
        )
        db.session.add(new_quiz)
        db.session.commit()
        flash('Quiz created successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating quiz: {str(e)}', 'danger')

    return redirect(url_for('admin_quizzes'))

@app.route('/add_question/<int:quiz_id>', methods=['POST'])
def add_question(quiz_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
    
    try:
        new_question = Question(
            quiz_id=quiz_id,
            question_text=request.form.get('questionText'),
            option_1=request.form.get('option1'),
            option_2=request.form.get('option2'),
            option_3=request.form.get('option3'),
            option_4=request.form.get('option4'),
            correct_option=request.form.get('correctOption'),
            marks=request.form.get('marks'),
            created_by=session['user_id']
        )
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding question: {str(e)}', 'danger')

    return redirect(url_for('admin_quizzes'))

@app.route('/update_quiz/<int:quiz_id>', methods=['POST'])
def update_quiz(quiz_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    try:
        quiz.chapter_id = request.form.get('chapterId')
        quiz.title = request.form.get('title')
        quiz.description = request.form.get('description')
        quiz.date_of_quiz = datetime.strptime(request.form.get('dateOfQuiz'), '%Y-%m-%d')
        quiz.time_duration = request.form.get('timeDuration')
        quiz.passing_score = request.form.get('passingScore')
        quiz.total_marks = request.form.get('totalMarks')
        
        db.session.commit()
        flash('Quiz updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating quiz', 'danger')

    return redirect(url_for('admin_quizzes'))

@app.route('/update_question/<int:question_id>', methods=['POST'])
def update_question(question_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
    
    question = Question.query.get_or_404(question_id)
    try:
        question.question_text = request.form.get('questionText')
        question.option_1 = request.form.get('option1')
        question.option_2 = request.form.get('option2')
        question.option_3 = request.form.get('option3')
        question.option_4 = request.form.get('option4')
        question.correct_option = request.form.get('correctOption')
        question.marks = request.form.get('marks')
        
        db.session.commit()
        flash('Question updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating question: {str(e)}', 'danger')

    return redirect(url_for('admin_quizzes'))

@app.route('/delete_quiz/<int:quiz_id>', methods=['POST'])
def delete_quiz(quiz_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))
    
    try:
        quiz = Quiz.query.get_or_404(quiz_id)
        Score.query.filter_by(quiz_id=quiz_id).delete()
        Question.query.filter_by(quiz_id=quiz_id).delete()
        db.session.delete(quiz)
        db.session.commit()
        flash('Quiz deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting quiz', 'danger')

    return redirect(url_for('admin_quizzes'))

@app.route('/delete_question/<int:question_id>', methods=['POST'])
def delete_question(question_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this feature', 'warning')
        return redirect(url_for('login'))

    try:
        question = Question.query.get_or_404(question_id)
        db.session.delete(question)
        db.session.commit()
        flash('Question deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting question', 'danger')

    return redirect(url_for('admin_quizzes'))

@app.route('/admin/summary')
def admin_summary():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please login as admin to access this page', 'warning')
        return redirect(url_for('login'))
    
    # Calculate statistics
    stats = {}
    
    # Quiz attempt distribution
    total_users = User.query.count()
    total_quizzes = Quiz.query.count()
    passed_scores = Score.query.filter(Score.score >= Quiz.passing_score).count()
    failed_scores = Score.query.filter(Score.score < Quiz.passing_score).count()
    total_possible_attempts = total_users * total_quizzes
    not_attempted = total_possible_attempts - (passed_scores + failed_scores)
    
    stats['passed_count'] = passed_scores
    stats['failed_count'] = failed_scores
    stats['not_attempted_count'] = not_attempted if not_attempted >= 0 else 0
    
    # Average scores by subject
    subjects = Subject.query.all()
    stats['subject_names'] = []
    stats['subject_scores'] = []
    
    for subject in subjects:
        stats['subject_names'].append(subject.name)
        avg_score = (
            db.session.query(func.avg(Score.score))
            .join(Quiz)
            .join(Chapter)
            .filter(Chapter.subject_id == subject.id)
            .scalar()
        )

        stats['subject_scores'].append("N/A" if avg_score is None else round(avg_score, 1))
    
    # User registration trends (last 7 days)
    stats['days'] = []
    stats['user_counts'] = []
    
    for i in range(6, -1, -1):
        date = datetime.now() - relativedelta(days=i)
        day_start = date.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = date.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        user_count = User.query.filter(
            User.created_at >= day_start,
            User.created_at <= day_end
        ).count()
        
        stats['days'].append(date.strftime('%b %d'))
        stats['user_counts'].append(user_count)

    # Add qualification distribution stats
    qualification_data = db.session.query(
        User.qualification,
        func.count(User.id)
    ).group_by(User.qualification).all()
    
    # Convert all data to strings after collection is complete
    stats['qualification_labels'] = str([qual[0] for qual in qualification_data])
    stats['qualification_counts'] = str([qual[1] for qual in qualification_data])
    stats['subject_names'] = str(stats['subject_names'])
    stats['subject_scores'] = str(stats['subject_scores'])
    stats['days'] = str(stats['days'])
    stats['user_counts'] = str(stats['user_counts'])
    
    return render_template('admin_summary.html', stats=stats)

@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'user':
        flash('Please login to access this page', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    stats = {}
    
    # Get user's quiz attempts
    completed_quizzes = Score.query.filter_by(user_id=user.id).count()
    total_quizzes = Quiz.query.count()
    not_attempted = total_quizzes - completed_quizzes
    
    # Calculate average score
    avg_score = db.session.query(func.avg(Score.score))\
        .filter_by(user_id=user.id).scalar() or 0
        
    # Highest score
    highest_score = db.session.query(func.max(Score.score))\
        .filter_by(user_id=user.id).scalar() or 0
    
    # Get subject-wise performance
    subject_scores = db.session.query(
        Subject.name,
        func.avg(Score.score).label('avg_score')
    ).join(Chapter, Subject.id == Chapter.subject_id)\
     .join(Quiz, Chapter.id == Quiz.chapter_id)\
     .join(Score, Quiz.id == Score.quiz_id)\
     .filter(Score.user_id == user.id)\
     .group_by(Subject.name).all()
    
    stats['subject_names'] = str([score[0] for score in subject_scores])
    stats['subject_scores'] = str([round(score[1], 2) for score in subject_scores])
    
    # Get recent quiz scores (last 5)
    recent_scores = Score.query.filter_by(user_id=user.id)\
        .order_by(Score.date.desc()).limit(5).all()
    
    stats['recent_dates'] = str([score.date.strftime('%Y-%m-%d') for score in recent_scores])
    stats['recent_scores'] = str([score.score for score in recent_scores])
    
    return render_template('user_dashboard.html',
                         user=user,
                         completed_quizzes=completed_quizzes,
                         avg_score=round(avg_score, 1),
                         highest_score=highest_score,
                         stats=stats)

@app.route('/user/subjects')
def user_subjects():
    if 'user_id' not in session or session.get('user_type') != 'user':
        flash('Please login to access this page', 'warning')
        return redirect(url_for('login'))
    
    search_query = request.args.get('search', '')
    
    if search_query:
        subjects = Subject.query.filter(
            db.or_(
                Subject.name.ilike(f'%{search_query}%'),
                Subject.description.ilike(f'%{search_query}%')
            )
        ).order_by(Subject.name.asc()).all()
    else:
        subjects = Subject.query.filter_by(is_active=True).order_by(Subject.name.asc()).all()
    
    return render_template('user_subjects.html', subjects=subjects)

@app.route('/user/quizzes')
def user_quizzes():
    if 'user_id' not in session or session.get('user_type') != 'user':
        flash('Please login to access this page', 'warning')
        return redirect(url_for('login'))
    
    search_query = request.args.get('search', '')
    
    # Get attempted quiz IDs for the current user
    attempted_quiz_ids = [score.quiz_id for score in 
                         Score.query.filter_by(user_id=session['user_id']).all()]
    
    # Base query for available quizzes
    available_quizzes_query = Quiz.query.filter(
        db.and_(
            Quiz.is_active == True,
            Quiz.id.notin_(attempted_quiz_ids)
        )
    )
    
    # Apply search if query exists
    if search_query:
        available_quizzes = available_quizzes_query.filter(
            db.or_(
                Quiz.title.ilike(f'%{search_query}%'),
                Quiz.description.ilike(f'%{search_query}%'),
                Quiz.chapter.has(Chapter.name.ilike(f'%{search_query}%')),
                Quiz.chapter.has(Chapter.subject.has(Subject.name.ilike(f'%{search_query}%')))
            )
        ).order_by(Quiz.date_of_quiz.desc()).all()
    else:
        available_quizzes = available_quizzes_query.order_by(
            Quiz.date_of_quiz.desc()
        ).all()
    
    # Get attempted quizzes
    attempted_quizzes = Score.query.filter_by(
        user_id=session['user_id']
    ).order_by(Score.date.desc()).all()
    
    return render_template('user_quizzes.html',
                         available_quizzes=available_quizzes,
                         attempted_quizzes=attempted_quizzes)

@app.route('/quiz/<int:quiz_id>/start')
def start_quiz(quiz_id):
    if 'user_id' not in session or session.get('user_type') != 'user':
        flash('Please login to access this page', 'warning')
        return redirect(url_for('login'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    
    if not questions:
        flash('No questions available for this quiz', 'warning')
        return redirect(url_for('user_quizzes'))
    
    # Store quiz start time in session
    session['quiz_start_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    session['quiz_id'] = quiz_id
    
    return render_template('quiz.html', quiz=quiz, questions=questions)

@app.route('/quiz/submit', methods=['POST'])
def submit_quiz():
    if 'user_id' not in session or session.get('user_type') != 'user':
        flash('Please login to access this page', 'warning')
        return redirect(url_for('login'))
    
    quiz_id = session.get('quiz_id')
    if not quiz_id:
        flash('Invalid quiz submission', 'danger')
        return redirect(url_for('user_quizzes'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Check if time limit exceeded
    start_time = datetime.strptime(session['quiz_start_time'], '%Y-%m-%d %H:%M:%S')
    time_taken = (datetime.now() - start_time).total_seconds() / 60  # in minutes
    
    if time_taken > quiz.time_duration:
        flash('Time limit exceeded!', 'danger')
        return redirect(url_for('user_quizzes'))
    
    # Calculate score
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    total_score = 0
    results = []
    
    for question in questions:
        user_answer = request.form.get(f'question_{question.id}')
        if user_answer and int(user_answer) == question.correct_option:
            total_score += question.marks
            results.append({
                'question': question.question_text,
                'correct': True,
                'marks': question.marks
            })
        else:
            results.append({
                'question': question.question_text,
                'correct': False,
                'marks': 0
            })
    
    # Save score
    new_score = Score(
        user_id=session['user_id'],
        quiz_id=quiz_id,
        score=total_score
    )
    db.session.add(new_score)
    db.session.commit()
    
    # Clear quiz session data
    session.pop('quiz_start_time', None)
    session.pop('quiz_id', None)
    
    return render_template('quiz_results.html', 
                         results=results, 
                         total_score=total_score,
                         passing_score=quiz.passing_score,
                         total_marks=quiz.total_marks)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))