from flask_restful import Api, Resource
from quiz_master.app import app
from quiz_master.models.models import *

api = Api(app)

class SubjectResource(Resource):
    def get(self):
        subjects = Subject.query.all()
        return { 'subjects' : [{
            'id': subject.id,
            'name': subject.name,
            'description': subject.description,
            'created_by': subject.created_by,
            'created_at': str(subject.created_at),
            'updated_at': str(subject.updated_at),
            'is_active': subject.is_active
        } for subject in subjects] }
    
class ChapterResource(Resource):
    def get(self):
        chapters = Chapter.query.all()
        return { 'chapters' : [{
            'id': chapter.id,
            'subject_id': chapter.subject_id,
            'name': chapter.name,
            'description': chapter.description,
            'sequence_number': chapter.sequence_number,
            'created_by': chapter.created_by,
            'created_at': str(chapter.created_at),
            'updated_at': str(chapter.updated_at),
            'is_active': chapter.is_active
        } for chapter in chapters] }
    
class QuizResource(Resource):
    def get(self):
        quizzes = Quiz.query.all()
        return { 'quizzes' : [{
            'id': quiz.id,
            'chapter_id': quiz.chapter_id,
            'title': quiz.title,
            'description': quiz.description,
            'date_of_quiz': str(quiz.date_of_quiz),
            'time_duration': quiz.time_duration,
            'passing_score': quiz.passing_score,
            'total_marks': quiz.total_marks,
            'created_by': quiz.created_by,
            'created_at': str(quiz.created_at),
            'updated_at': str(quiz.updated_at),
            'is_active': quiz.is_active
        } for quiz in quizzes] }
    
class ScoreResource(Resource):
    def get(self):
        scores = Score.query.all()
        return { 'scores' : [{
            'id': score.id,
            'user_id': score.user_id,
            'quiz_id': score.quiz_id,
            'score': score.score,
            'user_id': score.user_id,
            'date': str(score.date)
        } for score in scores] }
    
api.add_resource(SubjectResource, '/api/subjects')
api.add_resource(ChapterResource, '/api/chapters')
api.add_resource(QuizResource, '/api/quizzes')
api.add_resource(ScoreResource, '/api/scores')