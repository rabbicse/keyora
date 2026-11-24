# For running the example without a local Ruby.
FROM ruby:3.3-alpine AS build

# Puma has a C extension; the compiler stays in this stage.
RUN apk add --no-cache build-base
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle config set --global frozen true \
 && bundle install --jobs 4 \
 && rm -rf /usr/local/bundle/cache

FROM ruby:3.3-alpine

COPY --from=build /usr/local/bundle /usr/local/bundle
WORKDIR /app
COPY Gemfile Gemfile.lock app.rb auth.rb keyora.rb ./

# APP_ENV=production turns off Sinatra's development-only behaviour, including
# its restriction of the Host header to localhost.
ENV APP_ENV=production \
    HOST=0.0.0.0 \
    PORT=9012

RUN adduser -D -H app
USER app
EXPOSE 9012

CMD ["bundle", "exec", "ruby", "app.rb"]
