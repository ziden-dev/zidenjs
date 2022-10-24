import jsdoc from 'gulp-jsdoc3';
import gulp from 'gulp';

gulp.task('doc', function (cb) {
  gulp.src(['README.md', './build/**/*.js'], { read: false }).pipe(jsdoc(cb));
});
